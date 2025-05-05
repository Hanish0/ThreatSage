import os
import json
import time
from datetime import datetime

def generate_html_map(ip_data):
    """
    Generate an HTML file with a world map showing IP locations
    
    Args:
        ip_data: Dictionary of IP intelligence data
    
    Returns:
        Filename of the generated HTML map
    """
    os.makedirs("visualizations", exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"visualizations/ip-map-{timestamp}.html"
    
    locations = []
    for ip, data in ip_data.items():
        if "Error" not in data and "Coordinates" in data and data["Coordinates"] != "N/A":
            try:
                lat, lon = data["Coordinates"].split(",")
                locations.append({
                    "ip": ip,
                    "lat": float(lat),
                    "lon": float(lon),
                    "country": data.get("Country", "Unknown"),
                    "isp": data.get("ISP", "Unknown"),
                    "reputation": data.get("Reputation", "Unknown")
                })
            except (ValueError, AttributeError):
                continue
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ThreatSage IP Map Visualization</title>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                margin: 0;
                padding: 0;
                font-family: Arial, sans-serif;
            }}
            #header {{
                background-color: #2c3e50;
                color: white;
                padding: 10px 20px;
                text-align: center;
            }}
            #map {{
                height: 500px;
                width: 100%;
            }}
            .info-box {{
                padding: 10px;
                background: white;
                border: 1px solid #ccc;
                border-radius: 5px;
                margin-bottom: 5px;
            }}
            .suspicious {{
                color: #e74c3c;
                font-weight: bold;
            }}
            .clean {{
                color: #2ecc71;
            }}
        </style>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/leaflet.css" />
    </head>
    <body>
        <div id="header">
            <h1>ThreatSage IP Location Map</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        <div id="map"></div>
        
        <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/leaflet.js"></script>
        <script>
            // Initialize map
            var map = L.map('map').setView([20, 0], 2);
            
            // Add OpenStreetMap tile layer
            L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
            }}).addTo(map);
            
            // IP location data
            var ipLocations = {json.dumps(locations)};
            
            // Add markers for each IP
            ipLocations.forEach(function(loc) {{
                var markerColor = loc.reputation === "Suspicious" ? "#e74c3c" : "#2ecc71";
                
                var marker = L.circleMarker([loc.lat, loc.lon], {{
                    radius: 8,
                    fillColor: markerColor,
                    color: "#000",
                    weight: 1,
                    opacity: 1,
                    fillOpacity: 0.8
                }}).addTo(map);
                
                // Create popup content
                var popupContent = `
                    <div class="info-box">
                        <h3>IP: ${{loc.ip}}</h3>
                        <p><strong>Country:</strong> ${{loc.country}}</p>
                        <p><strong>ISP:</strong> ${{loc.isp}}</p>
                        <p><strong>Reputation:</strong> <span class="${{loc.reputation === "Suspicious" ? "suspicious" : "clean"}}">
                            ${{loc.reputation}}
                        </span></p>
                    </div>
                `;
                
                marker.bindPopup(popupContent);
            }});
        </script>
    </body>
    </html>
    """
    
    with open(filename, "w") as f:
        f.write(html_content)
        
    return filename

def generate_threat_chart(analysis_history):
    """
    Generate a chart showing threat scores over time
    
    Args:
        analysis_history: List of analysis results with timestamps and scores
        
    Returns:
        Filename of the generated HTML chart
    """
    os.makedirs("visualizations", exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"visualizations/threat-chart-{timestamp}.html"
    
    chart_data = []
    for entry in analysis_history:
        chart_data.append({
            "timestamp": entry.get("timestamp", time.time()),
            "score": entry.get("threat_score", 0),
            "ip": entry.get("ip", "Unknown")
        })
    
    chart_data.sort(key=lambda x: x["timestamp"])
    
    for entry in chart_data:
        entry["label"] = datetime.fromtimestamp(entry["timestamp"]).strftime("%Y-%m-%d %H:%M")
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ThreatSage Threat Score History</title>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                margin: 0;
                padding: 20px;
                font-family: Arial, sans-serif;
            }}
            #header {{
                background-color: #2c3e50;
                color: white;
                padding: 10px 20px;
                text-align: center;
                margin-bottom: 20px;
            }}
            #chart {{
                height: 400px;
                width: 100%;
                margin-top: 20px;
            }}
            .chart-container {{
                max-width: 1000px;
                margin: 0 auto;
            }}
        </style>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.1/chart.min.js"></script>
    </head>
    <body>
        <div id="header">
            <h1>ThreatSage Threat Score History</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="chart-container">
            <canvas id="threatChart"></canvas>
        </div>
        
        <script>
            // Chart data
            var chartData = {json.dumps(chart_data)};
            
            // Prepare data for Chart.js
            var labels = chartData.map(function(item) {{ return item.label; }});
            var scores = chartData.map(function(item) {{ return item.score; }});
            
            // Create the chart
            var ctx = document.getElementById('threatChart').getContext('2d');
            var threatChart = new Chart(ctx, {{
                type: 'line',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Threat Score',
                        data: scores,
                        backgroundColor: 'rgba(231, 76, 60, 0.2)',
                        borderColor: 'rgb(231, 76, 60)',
                        borderWidth: 2,
                        tension: 0.3,
                        pointRadius: 5,
                        pointBackgroundColor: 'rgb(231, 76, 60)'
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            max: 100,
                            title: {{
                                display: true,
                                text: 'Threat Score'
                            }}
                        }},
                        x: {{
                            title: {{
                                display: true,
                                text: 'Date/Time'
                            }}
                        }}
                    }},
                    plugins: {{
                        title: {{
                            display: true,
                            text: 'Security Threat Score History',
                            font: {{
                                size: 18
                            }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                afterLabel: function(context) {{
                                    var index = context.dataIndex;
                                    return 'IP: ' + chartData[index].ip;
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    """
    
    with open(filename, "w") as f:
        f.write(html_content)
        
    return filename