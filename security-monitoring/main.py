import requests
import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import time
import os
from collections import Counter
import chardet

import urllib3
from dotenv import load_dotenv

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Stratosphere Research Laboratory — лаборатория кибербезопасности Центра искусственного интеллекта факультета электротехники
# они предоставляют известные датасеты для защиты от информационных угроз
class StratosphereDataCollector:
    def __init__(self):
        self.datasets = [
            {
                'name': 'CTU-Malware-Capture-Botnet-42 (Neris)',
                'file': 'botnet-capture-20110810-neris.json',
                'description': 'Botnet traffic with Neris malware',
                'year': 2011,
                'infected_ip': '147.32.84.165'
            }
        ]

        self.logs = []
        self.malware_info = {}

    # загружает логи из локального файла
    def load_local_logs(self, filename='botnet-capture-20110810-neris.json'):
        if os.path.exists(filename):
            print(f"\nЗагрузка локального файла {filename}")


            try:
                # читаем весь файл как один JSON объект
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    data = json.load(f)

                # извлекаем информацию о потоке
                if 'flow' in data and 'hosts' in data['flow']:
                    hosts = data['flow']['hosts']

                    # создаем записи
                    self._extract_hosts(hosts, level=0)

                print(f"\nИзвлечено {len(self.logs)} записей из структуры hosts")

                self.malware_info = {
                    'dataset': 'CTU-13 Dataset - Neris Botnet',
                    'description': 'Real botnet traffic from CTU University',
                    'year': 2011,
                    'infected_ip': '147.32.84.165'
                }

                return True

            except json.JSONDecodeError as e:
                print(f"Ошибка при разборе JSON: {e}")
                return False
            except Exception as e:
                print(f"Ошибка при чтении файла: {e}")
                return False

        else:
            print(f"\nФайл {filename} не найден!")
            print("Текущая директория:", os.getcwd())
            return False

    def _extract_hosts(self, host_node, level=0, parent_name=None):
        if isinstance(host_node, dict):
            if 'name' in host_node:
                host_info = {
                    'timestamp': datetime.now().isoformat(),
                    'hostname': host_node['name'],
                    'level': level,
                    'parent': parent_name
                }
                self.logs.append(host_info)

                if 'children' in host_node and isinstance(host_node['children'], list):
                    for child in host_node['children']:
                        self._extract_hosts(child, level + 1, host_node['name'])

        elif isinstance(host_node, list):
            for item in host_node:
                self._extract_hosts(item, level, parent_name)


class VirusTotalChecker:
    def __init__(self):
        self.api_key = os.getenv("VIRUS_TOTAL_API_KEY")
        print(self.api_key)
        self.base_url = "https://www.virustotal.com/api/v3"
        self.cache_file = 'virus_total_cache.json'
        self.cache = self.load_cache()

    def load_cache(self):
        if os.path.exists(self.cache_file):
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        return {}

    def save_cache(self):
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)

    # проверка ip через Virus Total
    def check_ip(self, ip_address):
        if ip_address in self.cache:
            cache_time = datetime.fromisoformat(self.cache[ip_address]['timestamp'])
            if (datetime.now() - cache_time).seconds < 86400:
                return self.cache[ip_address]['data']

        # запрос к API
        try:
            headers = {'x-apikey': self.api_key}
            url = f"{self.base_url}/ip_addresses/{ip_address}"

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

                self.cache[ip_address] = {
                    'timestamp': datetime.now().isoformat(),
                    'data': stats
                }
                self.save_cache()

                return stats
            elif response.status_code == 429:
                print(f"Превышен лимит API (4 запроса в минуту). Ждем...")
                time.sleep(60)
                return self.check_ip(ip_address)
            else:
                return None

        except Exception as e:
            print(f"Ошибка при проверке {ip_address}: {e}")
            return None

    # проверка домена через Virus Total
    def check_domain(self, domain):
        domain = domain.strip().lower()

        # проверяем кэш
        cache_key = f"domain:{domain}"
        if cache_key in self.cache:
            cache_time = datetime.fromisoformat(self.cache[cache_key]['timestamp'])
            if (datetime.now() - cache_time).seconds < 86400:
                print(f"      (из кэша)")
                return self.cache[cache_key]['data']

        # Проверяем наличие API ключа
        if not self.api_key:
            print(f"      ОШИБКА: VirusTotal API ключ не найден. Добавьте VIRUS_TOTAL_API_KEY в .env файл")
            return None

        # запрос к API VirusTotal для проверки домена
        try:
            headers = {'x-apikey': self.api_key}
            url = f"{self.base_url}/domains/{domain}"

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

                # сохраняем в кэш
                self.cache[cache_key] = {
                    'timestamp': datetime.now().isoformat(),
                    'data': stats
                }
                self.save_cache()

                return stats
            elif response.status_code == 429:
                print(f"      Превышен лимит API (4 запроса в минуту). Ждем 60 секунд...")
                time.sleep(60)
                return self.check_domain(domain)
            else:
                print(f"      Ошибка API для домена {domain}: {response.status_code}")
                return None

        except requests.exceptions.SSLError as e:
            print(f"      SSL Ошибка: {e}")
            return None
        except requests.exceptions.Timeout:
            print(f"      Ошибка: Превышено время ожидания ответа от VirusTotal")
            return None
        except requests.exceptions.ConnectionError as e:
            print(f"      Ошибка подключения: {e}")
            return None
        except Exception as e:
            print(f"      Неизвестная ошибка при проверке домена {domain}: {type(e).__name__}: {e}")
            return None

    # проверка списка уникальных ip
    def check_ips_batch(self, ip_list):
        unique_ips = list(set(ip_list))[:20]
        results = []

        print(f"\nПроверка {len(unique_ips)} IP через VirusTotal...")

        for i, ip in enumerate(unique_ips, 1):
            print(f"    [{i}/{len(unique_ips)}] Проверка {ip}...")
            result = self.check_ip(ip)
            if result:
                results.append({
                    'ip': ip,
                    **result
                })
            if not self.demo_mode:
                time.sleep(15)  # Бесплатное API - 4 запроса в минуту
        return results

# класс, который отвечает за мониторинг
class SecurityMonitor:
    def __init__(self):
        self.logs = []
        self.threats = []
        self.vt_results = []
        self.infected_ip = None

    def load_stratosphere_data(self):

        collector = StratosphereDataCollector()

        # загружаем локальный файл
        if collector.load_local_logs('botnet-capture-20110810-neris.json'):
            self.logs = collector.logs
            self.infected_ip = collector.malware_info.get('infected_ip')

            print(f"\nЗагружено {len(self.logs)} записей")
            print(f"Зараженный IP: {self.infected_ip}")

    def analyze_threats(self):
        if not self.logs:
            print("\nНет данных для анализа")
            return []

        df = pd.DataFrame(self.logs)

        # собираем статистику по логам
        print(f"\nСтатистика датасета:")
        print(f"  Всего записей: {len(df)}")

        # анализируем домены
        if 'hostname' in df.columns:
            domains = df['hostname'].value_counts().head(10)
            print(f"\nТоп-10 доменов:")
            for domain, count in domains.items():
                print(f"  {domain}: {count}")

        threats_found = []

        # подозрительные домены
        suspicious_domains = ['.ru', '.cn', '.top', '.xyz', 'advertising.com', 'yieldmanager']
        if 'hostname' in df.columns:
            for _, row in df.iterrows():
                hostname = row.get('hostname', '')
                if any(susp in hostname for susp in suspicious_domains):
                    threat = {
                        'source': 'domain_analysis',
                        'type': 'suspicious_domain',
                        'domain': hostname,
                        'severity': 'HIGH',
                        'timestamp': row.get('timestamp', datetime.now().isoformat())
                    }
                    threats_found.append(threat)

        self.threats = threats_found
        print(f"\nНайдено {len(threats_found)} угроз")

        return threats_found

    def check_with_virustotal(self, vt_checker):
        if not self.threats:
            print("Нет угроз для проверки")
            return []

        # собираем уникальные домены из угроз
        suspicious_domains = list(set([t['domain'] for t in self.threats if 'domain' in t]))

        if not suspicious_domains:
            print("Нет доменов для проверки")
            return []

        print(f"\nПроверка {len(suspicious_domains)} доменов через VirusTotal...")

        vt_threats = []

        for i, domain in enumerate(suspicious_domains[:10], 1):
            print(f"    [{i}/{min(10, len(suspicious_domains))}] Проверка домена: {domain}")

            # Проверяем домен через VirusTotal
            result = vt_checker.check_domain(domain)

            if result:
                if result.get('malicious', 0) > 0:
                    threat = {
                        'source': 'virustotal',
                        'type': 'malicious_domain',
                        'domain': domain,
                        'malicious': result['malicious'],
                        'suspicious': result['suspicious'],
                        'severity': 'CRITICAL' if result['malicious'] > 5 else 'HIGH',
                        'timestamp': datetime.now().isoformat()
                    }
                    vt_threats.append(threat)

                    print(f"\n  Обнаружен вредоносный домен: {domain}")
                    print(f"      Вредоносных обнаружений: {result['malicious']}")
                    print(f"      Подозрительных обнаружений: {result['suspicious']}")
                else:
                    print(f"      Домен {domain} - чист")
            else:
                print(f"      Не удалось проверить домен {domain}")

            time.sleep(1)

        self.vt_results.extend(vt_threats)
        self.threats.extend(vt_threats)

        print(f"\nНайдено {len(vt_threats)} подтвержденных вредоносных доменов")
        return vt_threats

    # имитируем реагирование на угрозы
    def respond_to_threats(self):

        if not self.threats:
            print("Угроз не обнаружено")
            return

        # реагируем на угрозы, группируем по доменам
        suspicious_domains = list(set([t['domain'] for t in self.threats if 'domain' in t]))

        if suspicious_domains:
            print(f"\nОбнаружены подозрительные домены:")
            for domain in suspicious_domains[:10]:
                print(f"  - {domain}")
            print(f"\n- Доступ к подозрительным доменам заблокирован")
            print(f"- Включен DNS-мониторинг")

    # генерация текстового отчёта и графика
    def generate_report(self):
        if not self.logs:
            print("Нет данных для отчета")
            return

        report = {
            'generated_at': datetime.now().isoformat(),
            'data_source': 'CTU-13 Dataset - Neris Botnet',
            'infected_ip': self.infected_ip,
            'statistics': {
                'total_logs': len(self.logs),
                'total_threats': len(self.threats),
            },
            'threats': self.threats[:50]
        }

        # сохраняем в JSON
        with open('stratosphere_report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print("Отчет сохранен в stratosphere_report.json")

        # визуализируем
        self.create_visualization()

    def create_visualization(self):
        plt.figure(figsize=(12, 5))

        # топ доменов
        plt.subplot(1, 2, 1)
        if self.logs and 'hostname' in pd.DataFrame(self.logs).columns:
            df = pd.DataFrame(self.logs)
            domain_counts = df['hostname'].value_counts().head(10)
            domain_counts.plot(kind='barh', color='red', alpha=0.7)
            plt.title('Топ-10 доменов')
            plt.xlabel('Количество обращений')

        # типы угроз
        plt.subplot(1, 2, 2)
        if self.threats:
            threat_types = Counter([t['type'] for t in self.threats])
            plt.pie(threat_types.values(), labels=threat_types.keys(), autopct='%1.1f%%')
            plt.title('Типы обнаруженных угроз')

        plt.tight_layout()
        plt.savefig('stratosphere_analysis.png', dpi=100, bbox_inches='tight')
        print("График сохранен в stratosphere_analysis.png")
        plt.close()


def main():
    # инициализация
    virus_total_checker = VirusTotalChecker()
    monitor = SecurityMonitor()

    # загружаем данные со Stratosphere
    monitor.load_stratosphere_data()

    if monitor.logs:
        # выявляем угрозы
        monitor.analyze_threats()

        # проверяем через VirusTotal
        monitor.check_with_virustotal(virus_total_checker)

        # реагирование
        monitor.respond_to_threats()

        # генерация отчёта
        monitor.generate_report()
    else:
        print("\nНе удалось загрузить данные. Проверьте наличие файла с логами.")


if __name__ == "__main__":
    main()