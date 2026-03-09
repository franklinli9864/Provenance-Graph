import networkx as nx
import matplotlib.pyplot as plt
import re

def build_provenance_from_auth_log(file_path):
    G = nx.DiGraph()
    
    # 針對新格式的正規表達式
    # 範例: Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; rhost=218.188.2.4
    # 範例: Jul  3 10:05:25 combo ftpd[32069]: connection from 203.101.45.59
    log_pattern = re.compile(r'(\w{3}\s+\d+\s+[\d:]+)\s+combo\s+([^:\[\s]+)(?:\[(\d+)\])?:\s+(.*)')

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line: continue
                
                match = log_pattern.search(line)
                if match:
                    service = match.group(2)
                    pid = match.group(3) or "N/A"
                    message = match.group(4)
                    
                    # 1. 處理 SSH 失敗事件
                    if "sshd" in service and "authentication failure" in message:
                        ip_match = re.search(r"rhost=([\w\.\-]+)", message)
                        if ip_match:
                            source_ip = ip_match.group(1)
                            user_match = re.search(r"user=([\w\-]+)", message)
                            user = user_match.group(1) if user_match else "unknown"
                            
                            # 建立 IP -> Service -> User 的溯源鏈
                            G.add_edge(f"IP:{source_ip}", f"Svc:{service}", action="attack")
                            G.add_edge(f"Svc:{service}", f"User:{user}", action="failed_login")

                    # 2. 處理 FTP 連線事件
                    elif "ftpd" in service and "connection from" in message:
                        ip_match = re.search(r"connection from ([\d\.]+)", message)
                        if ip_match:
                            source_ip = ip_match.group(1)
                            G.add_edge(f"IP:{source_ip}", f"Svc:{service}", action="connect")

        return G
    except FileNotFoundError:
        print(f"錯誤：找不到檔案 {file_path}")
        return None

# --- 執行與繪圖 ---
log_file = "extracted_raw_logs.txt"
G = build_provenance_from_auth_log(log_file)

if G:
    # 如果圖太大，我們只畫前 30 個節點示範，避免畫面太亂
    nodes_to_show = list(G.nodes())[:30]
    subgraph = G.subgraph(nodes_to_show)
    
    plt.figure(figsize=(12, 10))
    pos = nx.spring_layout(subgraph, k=1.0)
    
    nx.draw_networkx_nodes(subgraph, pos, node_size=2000, node_color='salmon')
    nx.draw_networkx_labels(subgraph, pos, font_size=8)
    nx.draw_networkx_edges(subgraph, pos, edge_color='gray', arrows=True)
    
    plt.title("Provenance Graph: Auth Analysis (Attackers vs Services)")
    plt.axis('off')
    plt.show()
else:
    print("未能從 Log 中提取有效數據，請檢查檔案內容。")