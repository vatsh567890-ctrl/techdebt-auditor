# Technical Debt & Security Auditor — Starter Kit

This is a working starter app. It scans any public GitHub repo and gives you
a ranked "fix this first" backlog based on complexity, staleness, missing
tests, and risky code patterns.

## What's in this folder
- `analyzer.py` — the logic that clones a repo and scores files
- `app.py` — the visual dashboard (built with Streamlit)
- `requirements.txt` — the one dependency you need to install

## How to run it (step by step, zero assumed knowledge)

1. **Install Python** if you don't have it: go to python.org/downloads and
   install the latest version. During install on Windows, tick the box that
   says "Add Python to PATH."

2. **Open a terminal.**
   - Windows: search "Command Prompt" or "PowerShell" in the start menu
   - Mac: open the "Terminal" app

3. **Navigate into this folder.** Type (replace with your actual path):
   ```
   cd path/to/techdebt-auditor
   ```

4. **Install the one dependency:**
   ```
   pip install -r requirements.txt
   ```

5. **Run the app:**
   ```
   streamlit run app.py
   ```
   This will automatically open a browser tab with your dashboard.

6. **Test it:** paste any public GitHub repo URL, e.g.
   `https://github.com/pallets/flask` and click "Analyze Repo."

## How to extend this with Bob 2.0 (or any AI)
Open `analyzer.py` and find the function called `call_ai_for_explanation`.
Right now it just joins together the simple rule-based findings. To make it
smarter:
1. Get your Bob 2.0 API access working (via the hackathon setup guide).
2. Replace the inside of that function with a real API call that sends the
   file's metrics and asks for a plain-English risk explanation + a better
   effort estimate.
3. Everything else in the app stays the same — you're just upgrading one
   function.

## If something breaks
Copy the exact error message from your terminal and paste it into your AI
assistant (Bob 2.0, ChatGPT, or Claude) along with: "I got this error while
running a Streamlit app, here's the code: [paste app.py or analyzer.py],
here's the error: [paste error]. How do I fix it?"

## Ideas to add if you have extra time
- A "days since last commit" filter/slider
- Export the backlog as a CSV or as actual GitHub Issues
- A pie chart of high/medium/low risk file counts
- Let users upload a local folder instead of only a GitHub URL
