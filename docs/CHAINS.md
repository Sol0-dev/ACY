# Chain Recipes

## Chain 1: Subdomain Takeover -> ATO
Subdomain takeover + .target.com cookie scope = steal main app cookies

## Chain 2: IDOR + CORS -> Mass Data Exfil
IDOR reads other user data + CORS with credentials = cross-origin PII theft

## Chain 3: Self-XSS + CSRF -> Stored XSS
CSRF updates victim profile with XSS payload = admin session theft

## Chain 4: Open Redirect + OAuth -> Token Theft
redirect_uri bypass = auth code exfiltration = account takeover

## Chain 5: File Upload XSS + Admin Views -> ATO
SVG XSS in upload + admin panel displaying uploads = admin compromise

## Chain 6: SSRF + .env -> Full Compromise
SSRF to internal .env file = credential theft = backend access

## Chain 7: JWT alg:none + IDOR -> Mass ATO
Forge admin JWT + IDOR on all users = mass account takeover

## Chain 8: Business Logic + Race -> Infinite Money
Negative price + race coupon redemption = unlimited credits

## Chain 9: Prototype Pollution + DOM XSS -> Universal XSS
Pollute innerHTML + DOM sink = XSS without script tags

## Chain 10: Cache Poisoning + XSS -> Persistent XSS
Poison cache with XSS payload = all visitors get XSS
