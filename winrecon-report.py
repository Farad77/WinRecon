#!/usr/bin/env python3

"""
WinRecon Report Generator
Génère des rapports HTML interactifs basés sur les résultats d'énumération
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import base64

class WinReconReportGenerator:
    """Générateur de rapports WinRecon"""
    
    def __init__(self, config: Dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        
    def generate_html_report(self, results: Dict, output_file: Path) -> bool:
        """Génère un rapport HTML interactif"""
        try:
            html_content = self._build_html_report(results)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"Rapport HTML généré: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du rapport HTML: {e}")
            return False
    
    def _build_html_report(self, results: Dict) -> str:
        """Construit le contenu HTML du rapport"""
        
        # CSS et JavaScript intégrés
        css_content = self._get_css_styles()
        js_content = self._get_javascript()
        
        # Données pour le dashboard
        stats = self._calculate_statistics(results)
        timeline_data = self._build_timeline_data(results)
        vulnerability_data = self._build_vulnerability_data(results)
        
        html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WinRecon Report - {results.get('target', 'Unknown')}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.4/moment.min.js"></script>
    <style>{css_content}</style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="header-content">
                <h1><span class="logo">🛡️</span> WinRecon Report</h1>
                <div class="header-info">
                    <div class="info-item">
                        <span class="label">Target:</span>
                        <span class="value">{results.get('target', 'Unknown')}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Scan Date:</span>
                        <span class="value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                    </div>
                    <div class="info-item">
                        <span class="label">Domain:</span>
                        <span class="value">{results.get('domain', 'N/A')}</span>
                    </div>
                </div>
            </div>
        </header>

        <!-- Navigation -->
        <nav class="nav-tabs">
            <button class="tab-button active" onclick="showTab('dashboard')">Dashboard</button>
            <button class="tab-button" onclick="showTab('enumeration')">Énumération</button>
            <button class="tab-button" onclick="showTab('attacks')">Attaques</button>
            <button class="tab-button" onclick="showTab('vulnerabilities')">Vulnérabilités</button>
            <button class="tab-button" onclick="showTab('recommendations')">Recommandations</button>
            <button class="tab-button" onclick="showTab('technical')">Détails Techniques</button>
        </nav>

        <!-- Dashboard Tab -->
        <div id="dashboard" class="tab-content active">
            <div class="dashboard-grid">
                <!-- Statistics Cards -->
                <div class="stats-grid">
                    <div class="stat-card users">
                        <div class="stat-icon">👥</div>
                        <div class="stat-content">
                            <div class="stat-number">{stats.get('users', 0)}</div>
                            <div class="stat-label">Utilisateurs</div>
                        </div>
                    </div>
                    <div class="stat-card groups">
                        <div class="stat-icon">👥</div>
                        <div class="stat-content">
                            <div class="stat-number">{stats.get('groups', 0)}</div>
                            <div class="stat-label">Groupes</div>
                        </div>
                    </div>
                    <div class="stat-card computers">
                        <div class="stat-icon">💻</div>
                        <div class="stat-content">
                            <div class="stat-number">{stats.get('computers', 0)}</div>
                            <div class="stat-label">Ordinateurs</div>
                        </div>
                    </div>
                    <div class="stat-card vulnerabilities">
                        <div class="stat-icon">⚠️</div>
                        <div class="stat-content">
                            <div class="stat-number">{stats.get('vulnerabilities', 0)}</div>
                            <div class="stat-label">Vulnérabilités</div>
                        </div>
                    </div>
                </div>

                <!-- Charts -->
                <div class="chart-container">
                    <h3>Distribution des Services</h3>
                    <canvas id="servicesChart"></canvas>
                </div>

                <div class="chart-container">
                    <h3>Niveau de Risque</h3>
                    <canvas id="riskChart"></canvas>
                </div>

                <!-- Timeline -->
                <div class="timeline-container">
                    <h3>Timeline des Découvertes</h3>
                    <div id="timeline"></div>
                </div>
            </div>
        </div>

        <!-- Enumeration Tab -->
        <div id="enumeration" class="tab-content">
            <div class="enumeration-content">
                <h2>Résultats d'Énumération</h2>
                
                <!-- Users Section -->
                <div class="section">
                    <h3>👥 Utilisateurs Active Directory</h3>
                    <div class="table-container">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Nom d'utilisateur</th>
                                    <th>Nom complet</th>
                                    <th>Description</th>
                                    <th>Délégation</th>
                                </tr>
                            </thead>
                            <tbody>
                                {self._build_computers_table(results)}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Attacks Tab -->
        <div id="attacks" class="tab-content">
            <div class="attacks-content">
                <h2>Résultats des Attaques</h2>
                
                <!-- Kerberos Attacks -->
                <div class="section">
                    <h3>🎫 Attaques Kerberos</h3>
                    
                    <div class="attack-subsection">
                        <h4>ASREPRoasting</h4>
                        {self._build_asrep_section(results)}
                    </div>
                    
                    <div class="attack-subsection">
                        <h4>Kerberoasting</h4>
                        {self._build_kerberoasting_section(results)}
                    </div>
                </div>

                <!-- ADCS Attacks -->
                <div class="section">
                    <h3>🔐 Active Directory Certificate Services</h3>
                    {self._build_adcs_section(results)}
                </div>

                <!-- Coercion Attacks -->
                <div class="section">
                    <h3>🔀 Attaques de Coercition</h3>
                    {self._build_coercion_section(results)}
                </div>
            </div>
        </div>

        <!-- Vulnerabilities Tab -->
        <div id="vulnerabilities" class="tab-content">
            <div class="vulnerabilities-content">
                <h2>Analyse des Vulnérabilités</h2>
                {self._build_vulnerabilities_section(results)}
            </div>
        </div>

        <!-- Recommendations Tab -->
        <div id="recommendations" class="tab-content">
            <div class="recommendations-content">
                <h2>Recommandations de Sécurité</h2>
                {self._build_recommendations_section(results)}
            </div>
        </div>

        <!-- Technical Tab -->
        <div id="technical" class="tab-content">
            <div class="technical-content">
                <h2>Détails Techniques</h2>
                
                <div class="section">
                    <h3>🔧 Commandes Exécutées</h3>
                    <div class="commands-list">
                        {self._build_commands_section(results)}
                    </div>
                </div>

                <div class="section">
                    <h3>📊 Données Brutes (JSON)</h3>
                    <div class="json-container">
                        <pre id="rawData">{json.dumps(results, indent=2, ensure_ascii=False)}</pre>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        {js_content}
        
        // Données pour les graphiques
        const statsData = {json.dumps(stats)};
        const timelineData = {json.dumps(timeline_data)};
        const vulnerabilityData = {json.dumps(vulnerability_data)};
        
        // Initialiser les graphiques
        initializeCharts();
        initializeTimeline();
    </script>
</body>
</html>
"""
        return html

    def _get_css_styles(self) -> str:
        """Retourne les styles CSS pour le rapport"""
        return """
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    color: #333;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    background: rgba(255, 255, 255, 0.95);
    min-height: 100vh;
    box-shadow: 0 0 50px rgba(0, 0, 0, 0.1);
}

.header {
    background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
    color: white;
    padding: 2rem;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
}

.header-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
}

.header h1 {
    font-size: 2.5rem;
    font-weight: 300;
    display: flex;
    align-items: center;
    gap: 1rem;
}

.logo {
    font-size: 3rem;
}

.header-info {
    display: flex;
    gap: 2rem;
    flex-wrap: wrap;
}

.info-item {
    display: flex;
    flex-direction: column;
    align-items: center;
}

.info-item .label {
    font-size: 0.9rem;
    opacity: 0.8;
    margin-bottom: 0.25rem;
}

.info-item .value {
    font-size: 1.1rem;
    font-weight: 600;
}

.nav-tabs {
    display: flex;
    background: #f8f9fa;
    border-bottom: 2px solid #e9ecef;
    overflow-x: auto;
}

.tab-button {
    background: none;
    border: none;
    padding: 1rem 2rem;
    cursor: pointer;
    font-size: 1rem;
    font-weight: 500;
    color: #6c757d;
    transition: all 0.3s ease;
    border-bottom: 3px solid transparent;
    white-space: nowrap;
}

.tab-button:hover {
    background: #e9ecef;
    color: #495057;
}

.tab-button.active {
    color: #2c3e50;
    border-bottom-color: #3498db;
    background: white;
}

.tab-content {
    display: none;
    padding: 2rem;
    animation: fadeIn 0.3s ease-in;
}

.tab-content.active {
    display: block;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
}

.dashboard-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1rem;
    grid-column: 1 / -1;
}

.stat-card {
    background: white;
    border-radius: 15px;
    padding: 2rem;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
    display: flex;
    align-items: center;
    gap: 1.5rem;
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}

.stat-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 15px 35px rgba(0, 0, 0, 0.15);
}

.stat-icon {
    font-size: 3rem;
    width: 80px;
    height: 80px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
}

.stat-card.users .stat-icon { background: linear-gradient(135deg, #667eea, #764ba2); }
.stat-card.groups .stat-icon { background: linear-gradient(135deg, #f093fb, #f5576c); }
.stat-card.computers .stat-icon { background: linear-gradient(135deg, #4facfe, #00f2fe); }
.stat-card.vulnerabilities .stat-icon { background: linear-gradient(135deg, #fa709a, #fee140); }

.stat-number {
    font-size: 2.5rem;
    font-weight: 700;
    color: #2c3e50;
}

.stat-label {
    font-size: 1.1rem;
    color: #6c757d;
    font-weight: 500;
}

.chart-container {
    background: white;
    border-radius: 15px;
    padding: 2rem;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
}

.chart-container h3 {
    margin-bottom: 1rem;
    color: #2c3e50;
    font-weight: 600;
}

.timeline-container {
    grid-column: 1 / -1;
    background: white;
    border-radius: 15px;
    padding: 2rem;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
}

.section {
    background: white;
    border-radius: 15px;
    padding: 2rem;
    margin-bottom: 2rem;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
}

.section h3 {
    color: #2c3e50;
    margin-bottom: 1.5rem;
    font-size: 1.5rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.table-container {
    overflow-x: auto;
    border-radius: 10px;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
}

.data-table {
    width: 100%;
    border-collapse: collapse;
    background: white;
}

.data-table th {
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: white;
    padding: 1rem;
    text-align: left;
    font-weight: 600;
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.data-table td {
    padding: 1rem;
    border-bottom: 1px solid #e9ecef;
    vertical-align: top;
}

.data-table tbody tr:hover {
    background: #f8f9fa;
}

.attack-subsection {
    background: #f8f9fa;
    border-radius: 10px;
    padding: 1.5rem;
    margin-bottom: 1rem;
}

.attack-subsection h4 {
    color: #2c3e50;
    margin-bottom: 1rem;
    font-size: 1.2rem;
}

.vulnerability-item {
    background: #fff3cd;
    border: 1px solid #ffeaa7;
    border-radius: 10px;
    padding: 1.5rem;
    margin-bottom: 1rem;
}

.vulnerability-item.critical {
    background: #f8d7da;
    border-color: #f5c6cb;
}

.vulnerability-item.high {
    background: #fff3cd;
    border-color: #ffeaa7;
}

.vulnerability-item.medium {
    background: #d1ecf1;
    border-color: #bee5eb;
}

.vulnerability-item.low {
    background: #d4edda;
    border-color: #c3e6cb;
}

.recommendation-item {
    background: white;
    border-left: 4px solid #3498db;
    border-radius: 0 10px 10px 0;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
}

.recommendation-item.critical {
    border-left-color: #e74c3c;
}

.recommendation-item.important {
    border-left-color: #f39c12;
}

.commands-list {
    background: #2c3e50;
    color: #ecf0f1;
    border-radius: 10px;
    padding: 1.5rem;
    font-family: 'Courier New', monospace;
    font-size: 0.9rem;
    line-height: 1.6;
    overflow-x: auto;
}

.json-container {
    background: #2c3e50;
    color: #ecf0f1;
    border-radius: 10px;
    padding: 1.5rem;
    max-height: 500px;
    overflow: auto;
}

.json-container pre {
    font-family: 'Courier New', monospace;
    font-size: 0.8rem;
    line-height: 1.4;
    white-space: pre-wrap;
}

.badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.badge.critical { background: #e74c3c; color: white; }
.badge.high { background: #f39c12; color: white; }
.badge.medium { background: #3498db; color: white; }
.badge.low { background: #27ae60; color: white; }
.badge.info { background: #95a5a6; color: white; }

.progress-bar {
    background: #ecf0f1;
    border-radius: 10px;
    height: 20px;
    overflow: hidden;
    margin: 0.5rem 0;
}

.progress-fill {
    height: 100%;
    background: linear-gradient(135deg, #667eea, #764ba2);
    transition: width 0.3s ease;
}

@media (max-width: 768px) {
    .dashboard-grid {
        grid-template-columns: 1fr;
    }
    
    .header-content {
        flex-direction: column;
        text-align: center;
        gap: 1rem;
    }
    
    .header-info {
        justify-content: center;
    }
    
    .container {
        margin: 0;
    }
    
    .tab-content {
        padding: 1rem;
    }
}
"""

    def _get_javascript(self) -> str:
        """Retourne le code JavaScript pour le rapport"""
        return """
function showTab(tabName) {
    // Masquer tous les contenus d'onglets
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => {
        content.classList.remove('active');
    });
    
    // Désactiver tous les boutons d'onglets
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => {
        button.classList.remove('active');
    });
    
    // Afficher le contenu de l'onglet sélectionné
    document.getElementById(tabName).classList.add('active');
    
    // Activer le bouton de l'onglet sélectionné
    event.target.classList.add('active');
}

function initializeCharts() {
    // Graphique des services
    const servicesCtx = document.getElementById('servicesChart');
    if (servicesCtx && statsData.services) {
        new Chart(servicesCtx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(statsData.services),
                datasets: [{
                    data: Object.values(statsData.services),
                    backgroundColor: [
                        '#667eea',
                        '#764ba2',
                        '#f093fb',
                        '#f5576c',
                        '#4facfe',
                        '#00f2fe'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            usePointStyle: true
                        }
                    }
                }
            }
        });
    }
    
    // Graphique des risques
    const riskCtx = document.getElementById('riskChart');
    if (riskCtx && vulnerabilityData.riskLevels) {
        new Chart(riskCtx, {
            type: 'bar',
            data: {
                labels: ['Critique', 'Élevé', 'Moyen', 'Faible'],
                datasets: [{
                    label: 'Nombre de vulnérabilités',
                    data: [
                        vulnerabilityData.riskLevels.critical || 0,
                        vulnerabilityData.riskLevels.high || 0,
                        vulnerabilityData.riskLevels.medium || 0,
                        vulnerabilityData.riskLevels.low || 0
                    ],
                    backgroundColor: [
                        '#e74c3c',
                        '#f39c12',
                        '#3498db',
                        '#27ae60'
                    ],
                    borderRadius: 5,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }
}

function initializeTimeline() {
    const timelineContainer = document.getElementById('timeline');
    if (timelineContainer && timelineData.length > 0) {
        let timelineHTML = '<div class="timeline-list">';
        
        timelineData.forEach(item => {
            timelineHTML += `
                <div class="timeline-item">
                    <div class="timeline-time">${item.time}</div>
                    <div class="timeline-content">
                        <h4>${item.title}</h4>
                        <p>${item.description}</p>
                        ${item.details ? `<div class="timeline-details">${item.details}</div>` : ''}
                    </div>
                </div>
            `;
        });
        
        timelineHTML += '</div>';
        timelineContainer.innerHTML = timelineHTML;
    }
}

// Fonction pour exporter les données
function exportData(format) {
    const data = document.getElementById('rawData').textContent;
    
    if (format === 'json') {
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'winrecon_results.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
}

// Fonction pour filtrer les tableaux
function filterTable(tableId, searchValue) {
    const table = document.getElementById(tableId);
    const rows = table.getElementsByTagName('tr');
    
    for (let i = 1; i < rows.length; i++) {
        const row = rows[i];
        const cells = row.getElementsByTagName('td');
        let found = false;
        
        for (let j = 0; j < cells.length; j++) {
            if (cells[j].textContent.toLowerCase().includes(searchValue.toLowerCase())) {
                found = true;
                break;
            }
        }
        
        row.style.display = found ? '' : 'none';
    }
}

// Ajouter des styles CSS pour la timeline
const timelineStyles = `
    .timeline-list {
        position: relative;
        padding-left: 2rem;
    }
    
    .timeline-list::before {
        content: '';
        position: absolute;
        left: 1rem;
        top: 0;
        bottom: 0;
        width: 2px;
        background: linear-gradient(135deg, #667eea, #764ba2);
    }
    
    .timeline-item {
        position: relative;
        margin-bottom: 2rem;
        background: white;
        border-radius: 10px;
        padding: 1.5rem;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        margin-left: 2rem;
    }
    
    .timeline-item::before {
        content: '';
        position: absolute;
        left: -3rem;
        top: 1.5rem;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        background: #3498db;
        border: 3px solid white;
        box-shadow: 0 0 0 3px #3498db;
    }
    
    .timeline-time {
        font-size: 0.9rem;
        color: #6c757d;
        margin-bottom: 0.5rem;
    }
    
    .timeline-content h4 {
        color: #2c3e50;
        margin-bottom: 0.5rem;
    }
    
    .timeline-content p {
        color: #6c757d;
        line-height: 1.6;
    }
    
    .timeline-details {
        background: #f8f9fa;
        border-radius: 5px;
        padding: 1rem;
        margin-top: 1rem;
        font-size: 0.9rem;
        font-family: 'Courier New', monospace;
    }
`;

// Ajouter les styles à la page
const style = document.createElement('style');
style.textContent = timelineStyles;
document.head.appendChild(style);
"""

    def _calculate_statistics(self, results: Dict) -> Dict:
        """Calcule les statistiques pour le dashboard"""
        stats = {
            'users': 0,
            'groups': 0,
            'computers': 0,
            'vulnerabilities': 0,
            'services': {}
        }
        
        if 'enumeration' in results:
            enum_data = results['enumeration']
            stats['users'] = enum_data.get('users', 0)
            stats['groups'] = enum_data.get('groups', 0)
            stats['computers'] = enum_data.get('computers', 0)
        
        if 'vulnerabilities' in results:
            stats['vulnerabilities'] = len(results['vulnerabilities'])
        
        # Calculer la distribution des services
        services = ['SMB', 'LDAP', 'Kerberos', 'DNS', 'HTTP', 'RPC']
        for service in services:
            stats['services'][service] = 0  # À implémenter selon les données réelles
        
        return stats
    
    def _build_timeline_data(self, results: Dict) -> List[Dict]:
        """Construit les données de timeline"""
        timeline = []
        
        # Exemple de données de timeline basées sur les résultats
        if 'enumeration' in results:
            timeline.append({
                'time': '00:01',
                'title': 'Énumération initiale',
                'description': 'Découverte des utilisateurs, groupes et ordinateurs',
                'details': f"Trouvé {results['enumeration'].get('users', 0)} utilisateurs"
            })
        
        if 'attacks' in results:
            if 'kerberos' in results['attacks']:
                timeline.append({
                    'time': '00:05',
                    'title': 'Attaques Kerberos',
                    'description': 'ASREPRoasting et Kerberoasting exécutés',
                    'details': 'Recherche de comptes vulnérables'
                })
        
        return timeline
    
    def _build_vulnerability_data(self, results: Dict) -> Dict:
        """Construit les données de vulnérabilités"""
        vuln_data = {
            'riskLevels': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        if 'vulnerabilities' in results:
            for vuln in results['vulnerabilities']:
                risk_level = vuln.get('risk_level', 'medium').lower()
                if risk_level in vuln_data['riskLevels']:
                    vuln_data['riskLevels'][risk_level] += 1
        
        return vuln_data
    
    def _build_users_table(self, results: Dict) -> str:
        """Construit le tableau des utilisateurs"""
        if 'enumeration' not in results or 'user_details' not in results['enumeration']:
            return '<tr><td colspan="6">Aucune donnée utilisateur disponible</td></tr>'
        
        rows = []
        for user in results['enumeration']['user_details']:
            groups_str = ', '.join(user.get('groups', [])[:3])  # Limiter à 3 groupes
            if len(user.get('groups', [])) > 3:
                groups_str += '...'
            
            admin_badge = ''
            if user.get('admin_count', 0) > 0:
                admin_badge = '<span class="badge critical">Admin</span>'
            
            rows.append(f"""
                <tr>
                    <td>{user.get('username', 'N/A')}</td>
                    <td>{user.get('full_name', 'N/A')}</td>
                    <td>{user.get('description', 'N/A')}</td>
                    <td>{groups_str}</td>
                    <td>{user.get('spn', 'N/A')}</td>
                    <td>{admin_badge}</td>
                </tr>
            """)
        
        return '\n'.join(rows)
    
    def _build_groups_table(self, results: Dict) -> str:
        """Construit le tableau des groupes"""
        if 'enumeration' not in results or 'group_details' not in results['enumeration']:
            return '<tr><td colspan="4">Aucune donnée de groupe disponible</td></tr>'
        
        privileged_groups = [
            'Domain Admins', 'Enterprise Admins', 'Schema Admins',
            'Account Operators', 'Backup Operators'
        ]
        
        rows = []
        for group in results['enumeration']['group_details']:
            group_name = group.get('name', 'N/A')
            privilege_level = 'critical' if group_name in privileged_groups else 'medium'
            privilege_badge = f'<span class="badge {privilege_level}">{privilege_level.title()}</span>'
            
            members_count = len(group.get('members', []))
            
            rows.append(f"""
                <tr>
                    <td>{group_name}</td>
                    <td>{group.get('description', 'N/A')}</td>
                    <td>{members_count} membres</td>
                    <td>{privilege_badge}</td>
                </tr>
            """)
        
        return '\n'.join(rows)
    
    def _build_computers_table(self, results: Dict) -> str:
        """Construit le tableau des ordinateurs"""
        if 'enumeration' not in results or 'computer_details' not in results['enumeration']:
            return '<tr><td colspan="5">Aucune donnée d\'ordinateur disponible</td></tr>'
        
        rows = []
        for computer in results['enumeration']['computer_details']:
            delegation_badge = ''
            if computer.get('delegation'):
                delegation_badge = '<span class="badge high">Délégation</span>'
            
            rows.append(f"""
                <tr>
                    <td>{computer.get('name', 'N/A')}</td>
                    <td>{computer.get('os', 'N/A')}</td>
                    <td>{computer.get('os_version', 'N/A')}</td>
                    <td>{computer.get('description', 'N/A')}</td>
                    <td>{delegation_badge}</td>
                </tr>
            """)
        
        return '\n'.join(rows)
    
    def _build_asrep_section(self, results: Dict) -> str:
        """Construit la section ASREPRoasting"""
        if 'attacks' not in results or 'kerberos' not in results['attacks']:
            return '<p>Aucune donnée ASREPRoasting disponible</p>'
        
        asrep_data = results['attacks']['kerberos'].get('asrep_roasting', {})
        vulnerable_users = asrep_data.get('vulnerable_users', [])
        
        if not vulnerable_users:
            return '<div class="badge info">Aucun utilisateur vulnérable à ASREPRoasting détecté</div>'
        
        html = f'<div class="badge critical">{len(vulnerable_users)} utilisateurs vulnérables détectés</div>'
        html += '<ul>'
        for user in vulnerable_users:
            html += f'<li>{user}</li>'
        html += '</ul>'
        
        return html
    
    def _build_kerberoasting_section(self, results: Dict) -> str:
        """Construit la section Kerberoasting"""
        if 'attacks' not in results or 'kerberos' not in results['attacks']:
            return '<p>Aucune donnée Kerberoasting disponible</p>'
        
        kerb_data = results['attacks']['kerberos'].get('kerberoasting', {})
        service_accounts = kerb_data.get('service_accounts', [])
        
        if not service_accounts:
            return '<div class="badge info">Aucun compte de service avec SPN détecté</div>'
        
        html = f'<div class="badge high">{len(service_accounts)} comptes de service détectés</div>'
        html += '<ul>'
        for account in service_accounts:
            html += f'<li>{account}</li>'
        html += '</ul>'
        
        return html
    
    def _build_adcs_section(self, results: Dict) -> str:
        """Construit la section ADCS"""
        if 'attacks' not in results or 'adcs' not in results['attacks']:
            return '<p>Aucune donnée ADCS disponible</p>'
        
        adcs_data = results['attacks']['adcs']
        cas = adcs_data.get('certificate_authorities', {}).get('cas', [])
        vulnerabilities = adcs_data.get('esc_vulnerabilities', {})
        
        html = ''
        if cas:
            html += f'<div class="badge info">{len(cas)} autorités de certification détectées</div>'
        
        # Vérifier les vulnérabilités ESC
        vuln_count = sum(len(v) for v in vulnerabilities.values())
        if vuln_count > 0:
            html += f'<div class="badge critical">{vuln_count} vulnérabilités ESC détectées</div>'
        else:
            html += '<div class="badge info">Aucune vulnérabilité ESC détectée</div>'
        
        return html
    
    def _build_coercion_section(self, results: Dict) -> str:
        """Construit la section des attaques de coercition"""
        if 'attacks' not in results or 'coercion' not in results['attacks']:
            return '<p>Aucune donnée de coercition disponible</p>'
        
        coercion_data = results['attacks']['coercion']
        
        html = '<div class="coercion-results">'
        
        # PetitPotam
        petitpotam = coercion_data.get('petitpotam', {})
        if petitpotam.get('vulnerable', False):
            html += '<div class="badge critical">Vulnérable à PetitPotam</div>'
        else:
            html += '<div class="badge info">Non vulnérable à PetitPotam</div>'
        
        # Coercer
        coercer_data = coercion_data.get('coercer', {})
        techniques = coercer_data.get('techniques', [])
        if techniques:
            html += f'<div class="badge high">{len(techniques)} techniques de coercition disponibles</div>'
        
        html += '</div>'
        return html
    
    def _build_vulnerabilities_section(self, results: Dict) -> str:
        """Construit la section des vulnérabilités"""
        if 'vulnerabilities' not in results:
            return '<p>Aucune vulnérabilité détectée</p>'
        
        vulnerabilities = results['vulnerabilities']
        if not vulnerabilities:
            return '<div class="badge info">Aucune vulnérabilité critique détectée</div>'
        
        html = ''
        for i, vuln in enumerate(vulnerabilities):
            risk_level = vuln.get('risk_level', 'medium').lower()
            title = vuln.get('title', f'Vulnérabilité #{i+1}')
            description = vuln.get('description', 'Aucune description disponible')
            impact = vuln.get('impact', 'Impact non spécifié')
            remediation = vuln.get('remediation', 'Aucune recommandation disponible')
            
            html += f'''
                <div class="vulnerability-item {risk_level}">
                    <div class="vuln-header">
                        <h4>{title}</h4>
                        <span class="badge {risk_level}">{risk_level.upper()}</span>
                    </div>
                    <div class="vuln-content">
                        <p><strong>Description:</strong> {description}</p>
                        <p><strong>Impact:</strong> {impact}</p>
                        <p><strong>Remédiation:</strong> {remediation}</p>
                    </div>
                </div>
            '''
        
        return html
    
    def _build_recommendations_section(self, results: Dict) -> str:
        """Construit la section des recommandations"""
        recommendations = results.get('recommendations', [])
        
        if not recommendations:
            return '<div class="badge info">Aucune recommandation spécifique générée</div>'
        
        html = ''
        for i, recommendation in enumerate(recommendations):
            # Déterminer le niveau de priorité basé sur les mots-clés
            priority = 'important'
            if 'CRITIQUE' in recommendation.upper():
                priority = 'critical'
            elif 'ATTENTION' in recommendation.upper():
                priority = 'important'
            
            html += f'''
                <div class="recommendation-item {priority}">
                    <h4>Recommandation #{i+1}</h4>
                    <p>{recommendation}</p>
                </div>
            '''
        
        # Ajouter des recommandations générales
        general_recommendations = [
            {
                'title': 'Surveillance Continue',
                'content': 'Mettre en place une surveillance continue des événements de sécurité Active Directory avec des outils comme Windows Event Forwarding et SIEM.',
                'priority': 'important'
            },
            {
                'title': 'Principe du Moindre Privilège',
                'content': 'Appliquer le principe du moindre privilège pour tous les comptes utilisateur et de service. Réviser régulièrement les permissions.',
                'priority': 'critical'
            },
            {
                'title': 'Gestion des Mots de Passe',
                'content': 'Implémenter une politique de mots de passe robuste avec des mots de passe complexes, rotation régulière, et utilisation de gMSA pour les comptes de service.',
                'priority': 'critical'
            },
            {
                'title': 'Segmentation Réseau',
                'content': 'Segmenter le réseau pour limiter la propagation latérale. Isoler les contrôleurs de domaine et les serveurs critiques.',
                'priority': 'important'
            }
        ]
        
        html += '<h3>Recommandations Générales</h3>'
        for rec in general_recommendations:
            html += f'''
                <div class="recommendation-item {rec['priority']}">
                    <h4>{rec['title']}</h4>
                    <p>{rec['content']}</p>
                </div>
            '''
        
        return html
    
    def _build_commands_section(self, results: Dict) -> str:
        """Construit la section des commandes exécutées"""
        commands = results.get('commands_executed', [])
        
        if not commands:
            return '<p>Aucune commande enregistrée</p>'
        
        html = ''
        for i, cmd in enumerate(commands):
            html += f'''
                <div class="command-item">
                    <div class="command-header">Command #{i+1}</div>
                    <div class="command-content">{cmd}</div>
                </div>
            '''
        
        return html

    def generate_json_report(self, results: Dict, output_file: Path) -> bool:
        """Génère un rapport JSON structuré"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Rapport JSON généré: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du rapport JSON: {e}")
            return False
    
    def generate_csv_report(self, results: Dict, output_dir: Path) -> bool:
        """Génère des rapports CSV pour les différentes catégories"""
        try:
            import csv
            
            # Rapport des utilisateurs
            if 'enumeration' in results and 'user_details' in results['enumeration']:
                users_file = output_dir / 'users.csv'
                with open(users_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Username', 'Domain', 'Full Name', 'Description', 'Groups', 'SPN', 'Admin Count'])
                    
                    for user in results['enumeration']['user_details']:
                        writer.writerow([
                            user.get('username', ''),
                            user.get('domain', ''),
                            user.get('full_name', ''),
                            user.get('description', ''),
                            '; '.join(user.get('groups', [])),
                            user.get('spn', ''),
                            user.get('admin_count', 0)
                        ])
            
            # Rapport des groupes
            if 'enumeration' in results and 'group_details' in results['enumeration']:
                groups_file = output_dir / 'groups.csv'
                with open(groups_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Group Name', 'Domain', 'Description', 'Members Count'])
                    
                    for group in results['enumeration']['group_details']:
                        writer.writerow([
                            group.get('name', ''),
                            group.get('domain', ''),
                            group.get('description', ''),
                            len(group.get('members', []))
                        ])
            
            # Rapport des vulnérabilités
            if 'vulnerabilities' in results:
                vulns_file = output_dir / 'vulnerabilities.csv'
                with open(vulns_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Title', 'Risk Level', 'Description', 'Impact', 'Remediation'])
                    
                    for vuln in results['vulnerabilities']:
                        writer.writerow([
                            vuln.get('title', ''),
                            vuln.get('risk_level', ''),
                            vuln.get('description', ''),
                            vuln.get('impact', ''),
                            vuln.get('remediation', '')
                        ])
            
            self.logger.info(f"Rapports CSV générés dans: {output_dir}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération des rapports CSV: {e}")
            return False

    def generate_executive_summary(self, results: Dict, output_file: Path) -> bool:
        """Génère un résumé exécutif en format texte"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("="*60 + "\n")
                f.write("WINRECON - RÉSUMÉ EXÉCUTIF\n")
                f.write("="*60 + "\n\n")
                
                # Informations générales
                f.write(f"Cible: {results.get('target', 'N/A')}\n")
                f.write(f"Domaine: {results.get('domain', 'N/A')}\n")
                f.write(f"Date du scan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Statistiques principales
                stats = self._calculate_statistics(results)
                f.write("STATISTIQUES PRINCIPALES\n")
                f.write("-"*30 + "\n")
                f.write(f"Utilisateurs découverts: {stats.get('users', 0)}\n")
                f.write(f"Groupes découverts: {stats.get('groups', 0)}\n")
                f.write(f"Ordinateurs découverts: {stats.get('computers', 0)}\n")
                f.write(f"Vulnérabilités identifiées: {stats.get('vulnerabilities', 0)}\n\n")
                
                # Vulnérabilités critiques
                critical_vulns = [v for v in results.get('vulnerabilities', []) 
                                if v.get('risk_level', '').lower() == 'critical']
                
                f.write("VULNÉRABILITÉS CRITIQUES\n")
                f.write("-"*30 + "\n")
                if critical_vulns:
                    for vuln in critical_vulns:
                        f.write(f"• {vuln.get('title', 'Vulnérabilité sans titre')}\n")
                        f.write(f"  Impact: {vuln.get('impact', 'Non spécifié')}\n\n")
                else:
                    f.write("Aucune vulnérabilité critique identifiée.\n\n")
                
                # Recommandations principales
                f.write("RECOMMANDATIONS PRINCIPALES\n")
                f.write("-"*30 + "\n")
                recommendations = results.get('recommendations', [])
                if recommendations:
                    for i, rec in enumerate(recommendations[:5], 1):  # Top 5
                        f.write(f"{i}. {rec}\n\n")
                else:
                    f.write("Aucune recommandation spécifique générée.\n\n")
                
                # Conclusion
                f.write("CONCLUSION\n")
                f.write("-"*30 + "\n")
                risk_level = "ÉLEVÉ" if critical_vulns else "MODÉRÉ" if stats.get('vulnerabilities', 0) > 0 else "FAIBLE"
                f.write(f"Niveau de risque global: {risk_level}\n")
                f.write("Une analyse complète est disponible dans le rapport HTML détaillé.\n")
            
            self.logger.info(f"Résumé exécutif généré: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du résumé exécutif: {e}")
            return False

def generate_comprehensive_report(results: Dict, output_dir: Path, config: Dict, logger: logging.Logger) -> bool:
    """Génère tous les types de rapports"""
    try:
        # Créer le répertoire de sortie
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialiser le générateur de rapports
        report_gen = WinReconReportGenerator(config, logger)
        
        success = True
        
        # Rapport HTML interactif
        html_file = output_dir / 'winrecon_report.html'
        if not report_gen.generate_html_report(results, html_file):
            success = False
        
        # Rapport JSON
        json_file = output_dir / 'winrecon_results.json'
        if not report_gen.generate_json_report(results, json_file):
            success = False
        
        # Rapports CSV
        if config.get('reporting', {}).get('generate_csv', True):
            if not report_gen.generate_csv_report(results, output_dir):
                success = False
        
        # Résumé exécutif
        exec_summary_file = output_dir / 'executive_summary.txt'
        if not report_gen.generate_executive_summary(results, exec_summary_file):
            success = False
        
        if success:
            logger.info(f"Tous les rapports ont été générés avec succès dans: {output_dir}")
        
        return success
        
    except Exception as e:
        logger.error(f"Erreur lors de la génération des rapports: {e}")
        return False
