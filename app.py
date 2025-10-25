# app.py

import streamlit as st
import io
# Import your existing PhishFinder class
from phishfinder.analyzer import PhishFinder

st.set_page_config(layout="wide")


def display_analysis_report(indicators):
    # This function formats and displays the report in the Streamlit app

    st.markdown("## 1. Email Headers and Source")
    col1, col2 = st.columns(2)
    with col1:
        st.info(f"**Subject:** {indicators.get('Subject')}")
        st.info(f"**From:** {indicators.get('From')}")
        st.info(f"**Return-Path:** {indicators.get('Return-Path')}")
    with col2:
        st.warning(f"**Connecting IP:** {indicators.get('Connecting_IP')}")
        st.warning(f"**Originating Network:** {indicators.get('IP_ASN_Org')}")
        st.warning(f"**IP Country:** {indicators.get('IP_Country')}")

    st.markdown("---")
    st.markdown("## 2. Malicious Indicators")

    urls = indicators.get('URLs_Found', [])
    if urls:
        st.error(f"⚠️ **Potential Phishing URLs Found ({len(urls)}):**")
        for url in urls:
            st.text(f"  - {url}")
    else:
        st.success("✅ No external URLs found.")

    st.markdown("---")
    st.markdown("## 3. Recommended Action")
    st.markdown(f"**Check 'From' vs 'Return-Path':** Look for domain mismatch.")
    st.markdown(f"**Check Country/Network:** Investigate if the IP origin is unusual.")
    if urls:
        st.markdown(f"**Sandbox URLs:** Submitting all found URLs to a secure sandbox (e.g., VirusTotal) is MANDATORY.")


# --- STREAMLIT FRONT-END ---

st.title("🚨 PhishFinder: Raw Email Triage")
st.markdown("Paste the entire raw email source (including all headers) into the box below to begin analysis.")

# Create the large text area for pasting the raw email content
raw_content = st.text_area(
    "Paste Raw Email Source (.eml content) Here:",
    height=400,
    placeholder="Paste the entire email source starting with 'Received:' headers..."
)

# Button to trigger analysis
if st.button("Analyze Email Source"):
    if raw_content:
        with st.spinner('Running PhishFinder analysis...'):
            try:
                # The PhishFinder class requires a string input
                normalized_content = raw_content.replace('\n', '\r\n')
                analyzer = PhishFinder(normalized_content)
                indicators = analyzer.analyze_and_report()

                # Display results in the GUI
                st.header("Analysis Results")
                display_analysis_report(indicators)

            except Exception as e:
                st.error(f"An unexpected error occurred during analysis: {e}")
                st.warning("HINT: Ensure the entire raw text was copied correctly.")
    else:
        st.warning("Please paste the raw email source to begin analysis.")