# Firebase Token
Gets Firebase auth tokens (for development purposes only)

### Getting started
1. Create Firebase project
2. Setup Firebase authentication
3. Setup Google IDP
4. Create "Web" application for Firebase
5. Navigate to Web application credentials in GoogleCloud: `API & Services > Credentials > Web Client`
6. Add localhost to "Authorized redirect URIs" `e.g. http://localhost:5000/__/auth/handler`
7. Download JSON
8. Ensure Firebase service account exists in Firebase: `Project Settings > Service Accounts > Create Service Account (if doesn't already exist)`
9. Copy Firebase Admin APIKey in GoogleCloud: `API & Services > Credentials > API Keys > the one which says (auto created by Firebase)`
10. Get tokens `go run main.go --apiKey xyz123 --config ~/Downloads/yourfirebasewebappconfig.json`

### Quick install
`go install github.com/mousybusiness/firebase_token` then simply `firebase_token --help`

### Refreshing
`go run main.go  --apiKey xyz123 --config ~/Downloads/yourfirebasewebappconfig.json --refresh YOUR_REFRESH_TOKEN`

### IDToken only
`go run main.go  --apiKey xyz123 --config ~/Downloads/yourfirebasewebappconfig.json --refresh YOUR_REFRESH_TOKEN --token`

### Debugging
`LOG_LEVEL=debug go run main.go ...`
