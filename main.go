package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

type ZkillKill struct {
	KillmailID int `json:"killmail_id"`
	Zkb        struct {
		Points int  `json:"points"`
		Npc    bool `json:"npc"`
	} `json:"zkb"`
}

var (
	db          *sql.DB
	rdb         *redis.Client
	oauthConfig *oauth2.Config
	tmpl        = template.Must(template.ParseFiles("index.html"))
)

type PageData struct {
	LoggedIn bool
	CharID   string
}

type Contact struct {
	ContactID   int     `json:"contact_id"`
	ContactType string  `json:"contact_type"`
	Standing    float64 `json:"standing"`
}

type SearchResponse struct {
	Character []int `json:"character"`
}

func init() {
	log.Println("[init] Starting application initialization...")

	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}
	log.Printf("[init] Connecting to Redis at %s\n", redisURL)
	rdb = redis.NewClient(&redis.Options{Addr: redisURL})

	dbDir := "/app/data"
	if err := os.MkdirAll(dbDir, os.ModePerm); err != nil {
		log.Fatalf("[init] Failed to create data directory: %v\n", err)
	}

	dbPath := dbDir + "/eve.db"
	log.Printf("[init] Opening SQLite database at %s\n", dbPath)
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("[init] Failed to open database: %v\n", err)
	}

	log.Println("[init] Ensuring users table exists...")
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (char_id TEXT PRIMARY KEY, token TEXT)`)
	if err != nil {
		log.Fatalf("[init] Failed to create table: %v\n", err)
	}

	log.Println("[init] Configuring EVE OAuth2...")
	oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("EVE_CLIENT_ID"),
		ClientSecret: os.Getenv("EVE_CLIENT_SECRET"),
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://login.eveonline.com/v2/oauth/authorize",
			TokenURL:  "https://login.eveonline.com/v2/oauth/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: os.Getenv("EVE_CALLBACK_URL"),
		Scopes: []string{
			"esi-characters.read_contacts.v1",
			"esi-characters.write_contacts.v1",
			"esi-search.search_structures.v1",
		},
	}
	log.Println("[init] Initialization complete.")
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/process", processHandler)

	log.Println("[main] Server starting on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("eve_session")
	loggedIn := err == nil && cookie.Value != ""
	charID := ""
	if loggedIn {
		charID = cookie.Value
	}
	log.Printf("[indexHandler] Accessed root. LoggedIn: %v, CharID: '%s'\n", loggedIn, charID)
	tmpl.Execute(w, PageData{LoggedIn: loggedIn, CharID: charID})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[loginHandler] Initiating EVE SSO login flow...")
	url := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[callbackHandler] Received callback from EVE SSO.")
	code := r.URL.Query().Get("code")

	tok, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("[callbackHandler] OAuth Exchange Failed: %v\n", err)
		http.Error(w, fmt.Sprintf("Failed to exchange token: %v", err), http.StatusInternalServerError)
		return
	}

	charID, err := getCharIDFromJWT(tok.AccessToken)
	if err != nil {
		log.Printf("[callbackHandler] Failed to parse JWT: %v\n", err)
		http.Error(w, "Failed to parse JWT", http.StatusInternalServerError)
		return
	}
	log.Printf("[callbackHandler] Successfully authenticated CharID: %s\n", charID)

	tokenData, _ := json.Marshal(tok)
	_, err = db.Exec(`INSERT INTO users (char_id, token) VALUES (?, ?) ON CONFLICT(char_id) DO UPDATE SET token=excluded.token`, charID, string(tokenData))
	if err != nil {
		log.Printf("[callbackHandler] Failed to save session to DB: %v\n", err)
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	log.Printf("[callbackHandler] Session saved for CharID: %s. Setting cookie.\n", charID)
	http.SetCookie(w, &http.Cookie{Name: "eve_session", Value: charID, Path: "/", HttpOnly: true, Secure: true})
	http.Redirect(w, r, "/", http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[logoutHandler] User requested logout. Clearing cookie.")
	http.SetCookie(w, &http.Cookie{Name: "eve_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}

func processHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("eve_session")
	if err != nil {
		log.Println("[processHandler] Unauthorized request (no session cookie).")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	charID := cookie.Value
	log.Printf("[processHandler] Starting process run for CharID: %s\n", charID)

	var tokenData string
	err = db.QueryRow(`SELECT token FROM users WHERE char_id = ?`, charID).Scan(&tokenData)
	if err != nil {
		log.Printf("[processHandler] Session expired or missing in DB for CharID: %s\n", charID)
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}

	var tok oauth2.Token
	json.Unmarshal([]byte(tokenData), &tok)
	client := oauthConfig.Client(context.Background(), &tok)

	rawNames := r.FormValue("names")
	names := strings.Split(rawNames, "\n")
	skipNeutral := r.FormValue("skip_neutral") == "true"

	log.Printf("[processHandler] Received %d lines of names. Skip Neutral: %v\n", len(names), skipNeutral)

	var results strings.Builder

	log.Printf("[processHandler] Fetching current contacts for CharID: %s\n", charID)
	contacts, err := getContacts(context.Background(), client, charID)
	if err != nil {
		log.Printf("[processHandler] Error loading contacts: %v\n", err)
		fmt.Fprintf(w, "<div class='log-entry log-error'>Error loading your contacts from ESI: %v</div>", err)
		return
	}
	log.Printf("[processHandler] Loaded %d current contacts.\n", len(contacts))

	existingMap := make(map[int]*Contact)
	for i := range contacts {
		existingMap[contacts[i].ContactID] = &contacts[i]
	}

	toCreate := make(map[float64][]int)
	toUpdate := make(map[float64][]int)
	idToName := make(map[int]string)

	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		log.Printf("[processHandler] Processing character name: '%s'\n", name)

		searchURL := fmt.Sprintf("https://esi.evetech.net/latest/characters/%s/search/?categories=character&search=%s&strict=true", charID, url.QueryEscape(name))
		body, err := cachedGet(context.Background(), client, searchURL)
		if err != nil {
			log.Printf("[processHandler] ESI API Error searching '%s': %v\n", name, err)
			results.WriteString(fmt.Sprintf("<div class='log-entry log-error'>ESI API Error searching %s: %v</div>", name, err))
			continue
		}

		var searchResp SearchResponse
		if err := json.Unmarshal(body, &searchResp); err != nil || len(searchResp.Character) == 0 {
			log.Printf("[processHandler] Character '%s' not found in ESI.\n", name)
			results.WriteString(fmt.Sprintf("<div class='log-entry log-error'>Character '%s' not found in ESI.</div>", name))
			continue
		}

		targetID := searchResp.Character[0]
		idToName[targetID] = name
		log.Printf("[processHandler] Character '%s' resolved to ID: %d\n", name, targetID)

		isThreat, err := checkZKillboard(context.Background(), targetID)
		if err != nil {
			log.Printf("[processHandler] Error checking killmails for %d ('%s'): %v\n", targetID, name, err)
			results.WriteString(fmt.Sprintf("<div class='log-entry log-error'>Error checking killmails for %s: %v</div>", name, err))
			continue
		}

		targetStanding := 0.0
		existing := existingMap[targetID]

		if isThreat {
			targetStanding = -0.5
			if existing != nil {
				if existing.Standing < -0.5 {
					targetStanding = existing.Standing
				}
				if existing.Standing >= 0.0 {
					targetStanding = existing.Standing
				}
			}
		}

		log.Printf("[processHandler] Threat assessment for %d ('%s'): Threat=%v, TargetStanding=%.1f\n", targetID, name, isThreat, targetStanding)

		if existing == nil {
			if targetStanding == 0.0 && skipNeutral {
				log.Printf("[processHandler] Grouping Decision: SKIPPING CREATE for %d ('%s') - Neutral standing.\n", targetID, name)
				results.WriteString(fmt.Sprintf("<div class='log-entry log-info'>Skipped creating %s (would be neutral standing).</div>", name))
			} else {
				log.Printf("[processHandler] Grouping Decision: QUEUE CREATE for %d ('%s') at standing %.1f.\n", targetID, name, targetStanding)
				toCreate[targetStanding] = append(toCreate[targetStanding], targetID)
			}
		} else if existing.Standing != targetStanding {
			log.Printf("[processHandler] Grouping Decision: QUEUE UPDATE for %d ('%s') from %.1f to %.1f.\n", targetID, name, existing.Standing, targetStanding)
			toUpdate[targetStanding] = append(toUpdate[targetStanding], targetID)
		} else {
			log.Printf("[processHandler] Grouping Decision: NO ACTION for %d ('%s') - Already correct at %.1f.\n", targetID, name, targetStanding)
			results.WriteString(fmt.Sprintf("<div class='log-entry log-info'>%s is already correctly set at standing %.1f.</div>", name, targetStanding))
		}
	}

	// process bulk
	for standing, ids := range toCreate {
		for i := 0; i < len(ids); i += 100 {
			end := i + 100
			if end > len(ids) {
				end = len(ids)
			}
			chunk := ids[i:end]

			log.Printf("[processHandler] Executing bulk POST (Create) for %d contacts at standing %.1f...\n", len(chunk), standing)
			err := updateContactBulk(client, charID, chunk, standing, http.MethodPost)
			for _, id := range chunk {
				if err == nil {
					results.WriteString(fmt.Sprintf("<div class='log-entry log-success'>Added %s to contacts with standing %.1f.</div>", idToName[id], standing))
				} else {
					log.Printf("[processHandler] Bulk POST failed for %d: %v\n", id, err)
					results.WriteString(fmt.Sprintf("<div class='log-entry log-error'>Failed to add %s: %v</div>", idToName[id], err))
				}
			}
		}
	}

	for standing, ids := range toUpdate {
		for i := 0; i < len(ids); i += 100 {
			end := i + 100
			if end > len(ids) {
				end = len(ids)
			}
			chunk := ids[i:end]

			log.Printf("[processHandler] Executing bulk PUT (Update) for %d contacts at standing %.1f...\n", len(chunk), standing)
			err := updateContactBulk(client, charID, chunk, standing, http.MethodPut)
			for _, id := range chunk {
				if err == nil {
					results.WriteString(fmt.Sprintf("<div class='log-entry log-success'>Updated %s standing to %.1f.</div>", idToName[id], standing))
				} else {
					log.Printf("[processHandler] Bulk PUT failed for %d: %v\n", id, err)
					results.WriteString(fmt.Sprintf("<div class='log-entry log-error'>Failed to update %s: %v</div>", idToName[id], err))
				}
			}
		}
	}

	if len(toCreate) > 0 || len(toUpdate) > 0 {
		contactURL := fmt.Sprintf("https://esi.evetech.net/latest/characters/%s/contacts/", charID)
		log.Printf("[processHandler] Clearing Redis cache for contacts: cache:%s\n", contactURL)
		rdb.Del(context.Background(), "cache:"+contactURL)
	}

	log.Println("[processHandler] Process run completed.")
	fmt.Fprint(w, results.String())
}

func cachedGet(ctx context.Context, client *http.Client, urlStr string) ([]byte, error) {
	cacheKey := "cache:" + urlStr

	if cached, err := rdb.Get(ctx, cacheKey).Bytes(); err == nil {
		log.Printf("[cachedGet] CACHE HIT for: %s\n", urlStr)
		return cached, nil
	}

	log.Printf("[cachedGet] CACHE MISS for: %s. Fetching from network...\n", urlStr)
	req, _ := http.NewRequest("GET", urlStr, nil)

	if strings.Contains(urlStr, "zkillboard") {
		req.Header.Set("User-Agent", "Talion Starzise contactsync.cultofmagik.org")
		time.Sleep(200 * time.Millisecond) // be friendly when hitting zkill endpoints
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[cachedGet] Network request failed for %s: %v\n", urlStr, err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[cachedGet] Failed to read response body for %s: %v\n", urlStr, err)
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		log.Printf("[cachedGet] Network fetch SUCCESS (200) for: %s. Caching for 24h.\n", urlStr)
		rdb.Set(ctx, cacheKey, body, 24*time.Hour)
		return body, nil
	}

	log.Printf("[cachedGet] Network fetch HTTP %d for: %s\n", resp.StatusCode, urlStr)
	return nil, fmt.Errorf("HTTP %d - %s", resp.StatusCode, string(body))
}

func checkZKillboard(ctx context.Context, charID int) (bool, error) {
	urlStr := fmt.Sprintf("https://zkillboard.com/api/kills/characterID/%d/", charID)

	body, err := cachedGet(ctx, http.DefaultClient, urlStr)
	if err != nil {
		return false, err
	}

	var kills []ZkillKill
	if err := json.Unmarshal(body, &kills); err != nil {
		log.Printf("[checkZKillboard] Could not parse zKillboard JSON for %d (possibly empty). Assuming 0 points.\n", charID)
		return false, nil
	}

	totalPoints := 0
	for _, k := range kills {
		if !k.Zkb.Npc {
			totalPoints += k.Zkb.Points
		}
	}

	log.Printf("[checkZKillboard] Character %d has %d total non-NPC kill points.\n", charID, totalPoints)
	return totalPoints > 250, nil
}

func getContacts(ctx context.Context, client *http.Client, charID string) ([]Contact, error) {
	urlStr := fmt.Sprintf("https://esi.evetech.net/latest/characters/%s/contacts/", charID)

	body, err := cachedGet(ctx, client, urlStr)
	if err != nil {
		return nil, err
	}

	var contacts []Contact
	if err := json.Unmarshal(body, &contacts); err != nil {
		log.Printf("[getContacts] JSON Unmarshal error for contacts: %v\n", err)
		return nil, err
	}

	return contacts, nil
}

func updateContactBulk(client *http.Client, charID string, targetIDs []int, standing float64, method string) error {
	urlStr := fmt.Sprintf("https://esi.evetech.net/latest/characters/%s/contacts/?standing=%.1f", charID, standing)
	log.Printf("[updateContactBulk] Preparing to send %d IDs via %s to %s\n", len(targetIDs), method, urlStr)

	body, _ := json.Marshal(targetIDs)

	req, _ := http.NewRequest(method, urlStr, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		log.Printf("[updateContactBulk] ESI Error HTTP %d: %s\n", resp.StatusCode, string(b))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}

	log.Printf("[updateContactBulk] Successfully updated %d contacts.\n", len(targetIDs))
	return nil
}

func getCharIDFromJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	sub, ok := claims["sub"].(string)
	if !ok {
		return "", fmt.Errorf("no sub claim")
	}
	subParts := strings.Split(sub, ":")
	if len(subParts) == 3 {
		return subParts[2], nil
	}
	return "", fmt.Errorf("unrecognized sub format: %s", sub)
}
