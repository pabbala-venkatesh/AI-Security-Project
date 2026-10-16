
import streamlit as st
from security_checker import assess_risk

st.set_page_config(
    page_title="AI Security Checker",
    page_icon="🛡️",
    layout="centered",
)

st.title("AI Security Checker")
st.write("Check messages for common phishing warning signs.")

st.warning(
    "Educational prototype. This rule-based score "
    "cannot prove whether a message is safe or malicious."
)

message = st.text_area(
    "Paste a message to analyze",
    placeholder="Paste your test message here...",
    height=160,
)

if st.button("Analyze Message", type="primary"):
    if not message.strip():
        st.info("Please enter a message first.")
    else:
        result = assess_risk(message)

        st.subheader("Analysis Results")
        st.metric("Estimated Risk Score", f"{result['score']}/100")

        if result["level"] == "High":
            st.error("Risk Level: HIGH")
        elif result["level"] == "Medium":
            st.warning("Risk Level: MEDIUM")
        else:
            st.success("Risk Level: LOW")

        if result["findings"]:
            st.write("Warning signs found:")
            for finding in result["findings"]:
                st.write(f"- {finding}")
        else:
            st.write("No listed warning signs detected.")

        st.caption(
            "A low score does not guarantee safety. "
            "Always check links and requests independently."
        )
