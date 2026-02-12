# Smart Lab Monitoring and Exam Control System (LAN)

## Run server

Set admin password (optional):

- Linux/macOS:

```bash
export LABMON_ADMIN_PASSWORD=admin
```

Run:

```bash
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000
```

Open:

- `http://<server-ip>:8000/`

## Enroll a client

1. In dashboard, set admin password.
2. Click **Add Client** to generate enrollment code.
3. Put the enrollment code in `client/config.json` on that student PC.
4. Run client agent:

```bash
python client/agent.py
```
