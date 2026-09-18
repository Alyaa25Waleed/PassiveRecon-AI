import streamlit as st
import requests
import json
import dns.resolver
from openai import OpenAI
import time

# ============================================
# إعدادات الصفحة
# ============================================
st.set_page_config(
    page_title="PassiveRecon-AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================
# CSS مخصص للتصميم
# ============================================
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #00ff88;
        text-align: center;
        margin-bottom: 2rem;
        text-shadow: 2px 2px 4px rgba(0,255,136,0.3);
    }
    .sub-header {
        font-size: 1.2rem;
        color: #888;
        text-align: center;
        margin-bottom: 3rem;
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
    }
    .stButton>button:hover {
        background: linear-gradient(135deg, #00cc6a 0%, #009950 100%);
    }
</style>
""", unsafe_allow_html=True)

# ============================================
# العنوان الرئيسي
# ============================================
st.markdown('<h1 class="main-header">️ PassiveRecon-AI</h1>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Automated Passive Information Gathering & AI-Powered Pre-Engagement Analysis</p>', unsafe_allow_html=True)

# ============================================
# الشريط الجانبي (Sidebar)
# ============================================
with st.sidebar:
    st.header("️ Configuration")
    target = st.text_input("🎯 Target Domain", placeholder="example.com", help="Enter the domain to investigate")
    openai_key = st.text_input("🔑 OpenAI API Key", type="password", help="Optional: For AI analysis")
    
    st.markdown("---")
    st.subheader(" Features")
    st.checkbox("✅ Subdomain Enumeration", value=True, disabled=True)
    st.checkbox("✅ DNS Analysis", value=True, disabled=True)
    st.checkbox("✅ Wayback Machine", value=True, disabled=True)
    st.checkbox("✅ AI Analysis", value=True, disabled=True)
    
    st.markdown("---")
    st.caption("Built with ❤️ for Ethical Hackers")

# ============================================
# الدوال المساعدة
# ============================================
@st.cache_data(ttl=3600)
def get_subdomains(target):
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            subs = set()
            for entry in data:
                name = entry.get('name_value', '').replace('*.', '')
                if target in name and name != target:
                    subs.add(name)
            return list(subs)
    except:
        pass
    return []

@st.cache_data(ttl=3600)
def get_dns_info(target):
    records = {}
    for rtype in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(target, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
        except:
            records[rtype] = []
    return records

@st.cache_data(ttl=3600)
def get_wayback_urls(target):
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original&collapse=urlkey&limit=20"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            return [item[0] for item in data[1:]] if len(data) > 1 else []
    except:
        pass
    return []

def ai_analysis(target, data):
    if not openai_key:
        return "⚠️ OpenAI API Key not provided. Enter it in the sidebar to enable AI analysis."
    
    try:
        client = OpenAI(api_key=openai_key)
        prompt = f"""
        Act as a Senior Penetration Tester. Based on the following passive reconnaissance data for '{target}', 
        provide a concise Pre-Engagement Report focusing on:
        1. Infrastructure Summary
        2. Top 3 Potential Attack Vectors
        3. Interesting findings
        
        Data: {json.dumps(data, indent=2)}
        Keep it under 400 words.
        """
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"❌ AI Analysis failed: {e}"

# ============================================
# الواجهة الرئيسية
# ============================================
if not target:
    st.warning("⚠️ Please enter a target domain in the sidebar to begin.")
else:
    # زر البدء
    if st.button(" Start Reconnaissance", type="primary"):
        with st.spinner("Gathering intelligence..."):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # المرحلة 1: Subdomains
            status_text.text(" Enumerating subdomains...")
            subdomains = get_subdomains(target)
            progress_bar.progress(25)
            time.sleep(0.5)
            
            # المرحلة 2: DNS
            status_text.text("🌐 Resolving DNS records...")
            dns_records = get_dns_info(target)
            progress_bar.progress(50)
            time.sleep(0.5)
            
            # المرحلة 3: Wayback
            status_text.text(" Fetching historical URLs...")
            wayback_urls = get_wayback_urls(target)
            progress_bar.progress(75)
            time.sleep(0.5)
            
            # المرحلة 4: AI Analysis
            status_text.text("🤖 Analyzing with AI...")
            recon_data = {
                "subdomains_count": len(subdomains),
                "sample_subdomains": subdomains[:10],
                "dns_records": dns_records,
                "wayback_urls_count": len(wayback_urls)
            }
            ai_report = ai_analysis(target, recon_data)
            progress_bar.progress(100)
            status_text.text("✅ Reconnaissance complete!")
        
        st.success(f"Reconnaissance completed for **{target}**!")
        
        # ============================================
        # عرض النتائج في Tabs
        # ============================================
        tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🌐 Subdomains", " DNS Records", "🤖 AI Analysis"])
        
        with tab1:
            st.subheader("📊 Reconnaissance Summary")
            col1, col2, col3 = st.columns(3)
            col1.metric("Subdomains Found", len(subdomains))
            col2.metric("DNS Records", sum(len(v) for v in dns_records.values()))
            col3.metric("Historical URLs", len(wayback_urls))
            
            st.markdown("---")
            st.subheader(" Download Report")
            report_data = {
                "target": target,
                "subdomains": subdomains,
                "dns_records": dns_records,
                "wayback_urls": wayback_urls,
                "ai_analysis": ai_report
            }
            st.download_button(
                label="📥 Download JSON Report",
                data=json.dumps(report_data, indent=2),
                file_name=f"{target}_recon_report.json",
                mime="application/json"
            )
        
        with tab2:
            st.subheader(f"🌐 Subdomains for {target}")
            if subdomains:
                for sub in subdomains:
                    st.markdown(f"- `{sub}`")
            else:
                st.info("No subdomains found.")
        
        with tab3:
            st.subheader(f"🔍 DNS Records for {target}")
            for rtype, records in dns_records.items():
                with st.expander(f"{rtype} Records ({len(records)})"):
                    if records:
                        for record in records:
                            st.code(record, language="text")
                    else:
                        st.text("No records found.")
        
        with tab4:
            st.subheader("🤖 AI-Powered Pre-Engagement Analysis")
            st.markdown(ai_report)

# ============================================
# Footer
# ============================================
st.markdown("---")
st.caption("⚠️ This tool is for educational and authorized testing purposes only. Always obtain proper authorization before testing.")
