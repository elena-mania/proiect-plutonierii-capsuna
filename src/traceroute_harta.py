#harta impreuna cu codul de baza (ulterior personalizat in functie de cerintele noastre) este luata de aici https://plotly.com/python/lines-on-mapbox/

import plotly.express as px
import pandas as pd
import json

#aici preiau datele din fisierul intermediar 
with open("/home/alexandra-marina/Desktop/proiect-retele-2024-plutonierii-cap-una/src/traceroute_results.json", "r") as f:
    all_locations = json.load(f)
    
#trebuie sa filtrez locatiile valide care au lat si lon 
filtered_locations = []
for loc in all_locations:
    try:
        loc["lat"]
        loc["lon"]
        filtered_locations.append(loc)
    except KeyError:
        continue #daca nu are se trece mai departe 
        
df = pd.DataFrame(filtered_locations) 

fig = px.line_mapbox(
    df,
    lat="lat",
    lon="lon",
    color="ip",  # folosesc ip-ul pentru culoare ca sa desting traseele 
    hover_data=["regionName", "country"],
    zoom=1,
    height=600,
    title="Traceroute Routes"
)

fig.update_layout(mapbox_style="open-street-map", mapbox_zoom=4, mapbox_center_lat=41,
                  margin={"r":0,"t":0,"l":0,"b":0})

#pun datele intr-un fisier html (finally fara root care poate fi rulat de un utilizator fara privilegii)
output_file = "/home/alexandra-marina/Desktop/proiect-retele-2024-plutonierii-cap-una/src/traceroute_map.html"
fig.write_html(output_file)

print(f"Harta a fost salvata ca {output_file}")

