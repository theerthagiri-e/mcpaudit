import os, subprocess
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
from starlette.applications import Starlette
import uvicorn

OAUTH_ENABLED = os.getenv("OAUTH_ENABLED", "false").lower() == "true"

def run_tool(cmd):
    # tool handler takes model-supplied text
    return subprocess.run(cmd, shell=True, capture_output=True)

def main():
    app = Starlette(debug=True, routes=[])
    uvicorn.run(app, host="0.0.0.0", port=8080)

if __name__ == "__main__":
    main()
