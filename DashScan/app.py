from dash import Dash, dash_table, html, dcc
import dash_bootstrap_components as dbc
import plotly.express as px
import pandas as pd

external_stylesheets = [dbc.themes.BOOTSTRAP]
app = Dash(__name__, external_stylesheets = external_stylesheets)
colors = {'background': '#111111', 'text': '#FFFFFF'}

df = pd.read_csv('export.csv')
crit = []

#create the donut graph
for i in df['cvss']:
        if float(i) >= 9:
                crit.append("CRITICAL")
        elif float(i) >= 7:
                crit.append("HIGH")
        elif float(i) >= 4:
                crit.append("MEDIUM")
        else:
                crit.append("LOW")

df['criticity']=crit
df['cvss']=df['cvss'].astype(float)

scanned_assets = len(df['host'].value_counts(dropna=True))
discoverd_apps = len(df['Apps'].value_counts(dropna=True))
os_families = len(df['OS'].value_counts(dropna=False))
detected_cves = len(df['id'].value_counts(dropna=True))

card_1 = [dbc.CardBody([html.H3(children='Scanned Hosts', className='card-title'), html.H1(style={'textAlign': 'right', 'color': 'text'}, children=scanned_assets, className='card-text')])]
card_2 = [dbc.CardBody([html.H3(children='Discovered Apps', className='card-title'), html.H1(style={'textAlign': 'right', 'color': 'text'}, children=discoverd_apps, className='card-text')])]
card_3 = [dbc.CardBody([html.H3(children='OS Types', className='card-title'), html.H1(style={'textAlign': 'right', 'color': 'text'}, children=os_families, className='card-text')])]
card_4 = [dbc.CardBody([html.H3(children='Detected CVE', className='card-title'), html.H1(style={'textAlign': 'right', 'color': 'text'}, children=detected_cves, className='card-text')])]

row_1 = dbc.Row([dbc.Col(dbc.Card(card_1, color="dark", inverse=True)), dbc.Col(dbc.Card(card_2, color="dark", inverse=True))])
row_2 = dbc.Row([dbc.Col(dbc.Card(card_3, color="dark", inverse=True)), dbc.Col(dbc.Card(card_4, color="dark", inverse=True))])

fig = px.pie(df, values='cvss', names='criticity', hole=.7, color='criticity', color_discrete_map={'CRITICAL':'darkred', 'HIGH':'coral', 'MEDIUM':'orange', 'LOW':'darkseagreen'})
fig.update_layout(plot_bgcolor=colors['background'],paper_bgcolor=colors['background'],font_color=colors['text'])

#generate layout
app.layout = html.Div(style={'backgroundColor': colors['background']}, children=[

    html.H1(children='DashScan', style={'textAlign': 'left', 'color': colors['text']}),
    html.Div(html.H3(children='DashScan: Visualize CVEs in your network', style={'textAlign': 'left', 'color': colors['text']})),
    html.Div(row_1, style={'color': colors['text'], 'padding': '10px'}),
    html.Div(row_2, style={'color': colors['text'], 'padding': '10px'}),
    dcc.Graph(id='example-graph', figure=fig),
    html.H2(children='Scan results', style={'color': colors['text']}),
    html.Div(dash_table.DataTable(data=df.to_dict('records'), columns=[{'id': c, 'name': c} for c in df.columns], filter_action='native',
    style_cell={'textAlign': 'left', 'maxWidth': 0},
    style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
    style_data={'backgroundColor': 'rgb(50, 50, 50)', 'color': 'white', 'overflow': 'hidden', 'textOverflow': 'ellipsis'},
    page_size=20))

])

#run app
if __name__ == '__main__':
    app.run_server(debug=False)
