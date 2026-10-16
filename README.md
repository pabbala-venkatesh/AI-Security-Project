
# AI Security Checker 🛡️

A beginner-friendly cybersecurity project that analyzes text
messages for common phishing warning signs using Python.

## Features

- Detects suspicious phrases often used in phishing messages.
- Identifies URLs in messages.
- Flags selected URL-shortening services, including bit.ly
  and tinyurl.com.
- Calculates a rule-based risk score from 0 to 100.
- Displays Low, Medium, or High risk levels.
- Provides a Streamlit web interface.
- Includes automated unit tests.

## Technologies Used

- Python
- Streamlit
- Regular expressions
- Python unittest

## Project Structure

```text
AI-Security-Project/
├── app.py
├── security_checker.py
├── tests/
│   └── test_security_checker.py
├── README.md
└── .gitignore
```

## How to Run

1. Install Python 3.
2. Open a terminal in the project directory.
3. Install Streamlit:

   ```bash
   python -m pip install streamlit
   ```

4. Start the web application:

   ```bash
   python -m streamlit run app.py
   ```

5. Open the local URL displayed in the terminal.

## Run Automated Tests

Run:

```bash
python -m unittest discover -s tests -v
```

## How Risk Scoring Works

The prototype assigns points for selected suspicious phrases
and detected URLs. It also adds points for selected shortened
URL domains.

The score is a simple heuristic, not a validated probability
of phishing.

## Limitations

- It does not verify whether a URL is malicious.
- It does not visit links or inspect web pages.
- It may miss sophisticated phishing attempts.
- A low score does not guarantee that a message is safe.
- Shortened URLs are not automatically malicious.

## Future Improvements

- Add more URL and message-analysis tests.
- Improve domain and URL parsing.
- Add safer, explainable detection rules.
- Deploy a public demo.
- Explore machine-learning-based detection.

## Disclaimer

This project is for educational purposes. Always verify
suspicious messages independently and never share passwords
or one-time passwords with untrusted websites.
