import streamlit as st
import requests
import json
import dns.resolver
from openai import OpenAI
import time

# ============================================
# Page Configuration
# ============================================
st.set_page_config(
    page_title="PassiveRecon-AI",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================
# Custom CSS Styling
# ============================================
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #00ff88;
        text-align: center;
        margin-bottom: 0.5rem;
        text-shadow: 2px 2px 4px rgba(0,255,136,0.3);
    }
    .sub-header {
        font-size: 1.1rem;
        color: #a0a0a0;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #1e1e2e 0%, #2d2d44 100%);
        padding: 1rem;
        border-radius: 10px;
        border-left: 4px solid #00ff88;
        margin-bottom: 1rem;
    }
    .stButton>button {
        background: linear-gradient(135deg, #00ff88 0%, #00cc6a 100%);
        color: #000;
        font-weight: bold;
        border: none;
        padding: 0.5rem 2rem;
        border-radius: 5px;
        width: 100%;
    }
    .stButton>button:hover {
        background: linear-gradient(135deg, #00cc6a 0%, #009950 100%);
        color: #fff;
    }
</style>
""", unsafe_allow_html=True)

# ============================================
# Header Section
# ============================================
st.markdown('<h1 class="main-header">PassiveRecon-AI</h1>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Automated Passive Information Gathering & AI-Powered Pre-Engagement Analysis</p>', unsafe_allow_html=True)

# ============================================
# Sidebar Configurations
# ============================================
with st.sidebar:
    st.header("Configuration")
    target = st.text_input("Target Domain", placeholder="example.com", help="Enter the main domain to investigate").strip().lower()
    openai_key = st.text_input("OpenAI API Key", type="password", help="Optional: Required for generating AI threat reports").strip()
    
    st.markdown("---")
    st.subheader("Active Modules")
    st.checkbox("Subdomain Enumeration (crt.sh)", value=True, disabled=True)
    st.checkbox("DNS Analysis (dnspython)", value=True, disabled=True)
    st.checkbox("Wayback Machine (Archive.org)", value=True, disabled=True)
    st.checkbox("AI Threat Report (OpenAI)", value=True, disabled=True)
    
    st.markdown("---")
    st.caption("Built for Ethical Hackers & Security Researchers")

# ============================================
# Helper Functions with Caching
# ============================================
@st.cache_data(ttl=3600, show_spinner=False)
def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            subs = set()
            for entry in data:
                name = entry.get('name_value', '').lower()
                for sub_name in name.split('\n'):
                    sub_name = sub_name.replace('*.', '').strip()
                    if domain in sub_name and sub_name != domain:
                        subs.add(sub_name)
            return sorted(list(subs))
    except Exception:
        pass
    return []

@st.cache_data(ttl=3600, show_spinner=False)
def get_dns_info(domain):
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    
    for rtype in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
        except Exception:
            records[rtype] = []
    return records

@st.cache_data(ttl=3600, show_spinner=False)
def get_wayback_urls(domain):
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=50"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            if len(data) > 1:
                return [item[0] for item in data[1:]]
    except Exception:
        pass
    return []

def ai_analysis(domain, data, api_key):
    if not api_key:
        return "OpenAI API Key was not provided. Please enter your API key in the sidebar to generate an AI intelligence report."
    
    try:
        client = OpenAI(api_key=api_key)
        prompt = f"""
        Act as a Senior Penetration Tester and Security Architect.
        Analyze the following passive reconnaissance footprint for the domain '{domain}' and write a concise Pre-Engagement Assessment Report.

        Target Footprint:
        {json.dumps(data, indent=2)}

        Structure your response with clear sections:
        1. Executive Infrastructure Summary
        2. Top 3 Potential Attack Vectors (based on DNS/Subdomains/Wayback findings)
        3. High-Value Intelligence & Recommendations for Active Scanning Phase

        Keep the tone professional, objective, and concise (under 400 words).
        """
        
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AI Analysis generation failed: {str(e)}"

# ============================================
# Main Application Logic
# ============================================
if not target:
    st.info("Please enter a target domain (e.g., example.com) in the sidebar to initialize the reconnaissance workflow.")
else:
    if "scan_data" not in st.session_state:
        st.session_state.scan_data = None

    if st.button("Start Reconnaissance", type="primary"):
        with st.spinner("Gathering intelligence..."):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # Step 1: Subdomain Enumeration
            status_text.text("Enumerating subdomains via Certificate Transparency logs...")
            subdomains = get_subdomains(target)
            progress_bar.progress(25)
            time.sleep(0.3)
            
            # Step 2: DNS Resolution
            status_text.text("Resolving primary DNS records (A, MX, NS, TXT)...")
            dns_records = get_dns_info(target)
            progress_bar.progress(50)
            time.sleep(0.3)
            
            # Step 3: Wayback Discovery
            status_text.text("Querying Wayback Machine for historical endpoints...")
            wayback_urls = get_wayback_urls(target)
            progress_bar.progress(75)
            time.sleep(0.3)
            
            # Step 4: AI Threat Analysis
            status_text.text("Generating AI Threat Assessment Report...")
            recon_summary = {
                "subdomains_count": len(subdomains),
                "sample_subdomains": subdomains[:15],
                "dns_records": dns_records,
                "wayback_urls_count": len(wayback_urls),
                "sample_wayback_urls": wayback_urls[:10]
            }
            ai_report = ai_analysis(target, recon_summary, openai_key)
            progress_bar.progress(100)
            status_text.empty()
            progress_bar.empty()

            st.session_state.scan_data = {
                "target": target,
                "subdomains": subdomains,
                "dns_records": dns_records,
                "wayback_urls": wayback_urls,
                "ai_report": ai_report
            }

    if st.session_state.scan_data and st.session_state.scan_data["target"] == target:
        results = st.session_state.scan_data
        
        st.success(f"Reconnaissance completed for **{target}**!")
        
        tab1, tab2, tab3, tab4 = st.tabs([
            "Overview", 
            "Subdomains", 
            "DNS Records", 
            "AI Threat Report"
        ])
        
        # Tab 1: Overview
        with tab1:
            st.subheader("Reconnaissance Summary")
            col1, col2, col3 = st.columns(3)
            col1.metric("Subdomains Discovered", len(results["subdomains"]))
            col2.metric("DNS Records Resolved", sum(len(v) for v in results["dns_records"].values()))
            col3.metric("Historical Endpoints", len(results["wayback_urls"]))
            
            st.markdown("---")
            st.subheader("Export Intelligence Report")
            export_payload = {
                "target": results["target"],
                "subdomains": results["subdomains"],
                "dns_records": results["dns_records"],
                "wayback_urls": results["wayback_urls"],
                "ai_analysis": results["ai_report"]
            }
            st.download_button(
                label="Download Full JSON Report",
                data=json.dumps(export_payload, indent=2),
                file_name=f"{results['target']}_recon_report.json",
                mime="application/json"
            )

        # Tab 2: Subdomains
        with tab2:
            st.subheader(f"Discovered Subdomains ({len(results['subdomains'])})")
            if results["subdomains"]:
                st.code("\n".join(results["subdomains"]), language="text")
            else:
                st.info("No subdomains found for this target.")

        # Tab 3: DNS Records
        with tab3:
            st.subheader(f"DNS Records for {results['target']}")
            for rtype, records in results["dns_records"].items():
                with st.expander(f"{rtype} Records ({len(records)})", expanded=True if records else False):
                    if records:
                        for record in records:
                            st.code(record, language="text")
                    else:
                        st.caption("No records found.")

        # Tab 4: AI Analysis
        with tab4:
            st.subheader("AI-Powered Threat Assessment")
            st.markdown(results["ai_report"])

# ============================================
# Footer
# ============================================
st.markdown("---")
st.caption("Disclaimer: This tool is intended solely for educational and authorized security testing. Always secure explicit permission before conducting any reconnaissance.")
