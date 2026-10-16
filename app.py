
import streamlit as st
from security_checker import assess_risk

st.set_page_config(
    page_title="AI Security Checker",
    page_icon="🛡️",
    layout="centered",
)

st.title("🛡️ AI Security Checker")
st.write(
    "Analyze messages for common phishing warning signs."
)

st.info(
    "Educational project: results are rule-based indicators, "
    "not proof that a message is safe or malicious."
)

message = st.text_area(
    "Paste a message to analyze",
    placeholder=(
        "Example: Urgent action required! "
        "Verify your account at https://bit.ly/example"
    ),
    height=160,
)

if st.button("Analyze Message", type="primary"):
    if not message.strip():
        st.warning("Please enter a message first.")
    else:
        result = assess_risk(message)

        st.subheader("Analysis Results")

        col1, col2 = st.columns(2)
        col1.metric(
            "Risk Score",
            f"{result['score']}/100",
        )
        col2.metric(
            "Risk Level",
            result["level"].upper(),
        )

        if result["level"] == "High":
            st.error("High risk: review this message carefully.")
        elif result["level"] == "Medium":
            st.warning("Medium risk: check the warning signs.")
        else:
            st.success(
                "Low risk: no strong indicators were detected "
                "by the current rules."
            )

        st.subheader("Warning Signs")

        if result["findings"]:
            for finding in result["findings"]:
                st.write(f"- {finding}")
        else:
            st.write("No listed warning signs were detected.")

        st.caption(
            "This tool does not open or verify links. "
            "Never enter passwords or OTPs on an untrusted site."
        )
