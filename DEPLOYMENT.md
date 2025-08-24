# Proxy Deployment Guide

## Local Development Setup

1. **Create .env file with your proxy credentials**:
   ```bash
   # Static Proxy Configuration for proxy-cheap.com
   STATIC_PROXY_HOST=your_proxy_ip_here
   STATIC_PROXY_PORT=your_proxy_port_here
   STATIC_PROXY_USERNAME=your_username_here
   STATIC_PROXY_PASSWORD=your_password_here
   ```

2. **Ensure .env is in .gitignore** (already done):
   ```
   .env
   ```

3. **Test locally**:
   ```bash
   python3 main.py
   ```

## Google Cloud Deployment

### Set Environment Variables

Use Google Cloud Console or gcloud CLI to set environment variables:

```bash
gcloud config set project YOUR_PROJECT_ID

# Set proxy configuration (replace with your actual values)
gcloud app deploy --set-env-vars STATIC_PROXY_HOST=YOUR_PROXY_IP,STATIC_PROXY_PORT=YOUR_PROXY_PORT,STATIC_PROXY_USERNAME=YOUR_USERNAME,STATIC_PROXY_PASSWORD=YOUR_PASSWORD
```

Or in `app.yaml`:
```yaml
runtime: python39

env_variables:
  STATIC_PROXY_HOST: "YOUR_PROXY_IP"
  STATIC_PROXY_PORT: "YOUR_PROXY_PORT"  
  STATIC_PROXY_USERNAME: "YOUR_USERNAME"
  STATIC_PROXY_PASSWORD: "YOUR_PASSWORD"
```

**IMPORTANT**: Never commit `app.yaml` with credentials to git!

## Security Notes

- ✅ `.env` file is in `.gitignore`
- ✅ Credentials are loaded from environment variables
- ✅ No hardcoded credentials in source code
- ✅ Production uses Google Cloud environment variables
- ✅ Development uses local `.env` file

## Blocked Domains (Using Proxy)

The following library domains are routed through the static proxy:
- `bibliotekskatalog.falkenberg.se` (Falkenberg)
- `encore.gotlib.goteborg.se` (Göteborg)
- `kohaopac.alingsas.se` (Alingsås)

All other domains connect directly without proxy.

## Performance Expectations

- **Direct connections**: 100-500ms
- **Proxy connections**: 500ms-2 seconds
- **Success rate**: 95%+
- **Cost**: $1.27/month for residential IP