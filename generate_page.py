from datetime import datetime
import pandas as pd

from cve_data import CveDataSet

# CSVやsqlite3からのデータをロードします
input_vuln_data = CveDataSet()
# Merge the respective data
df_kev_epss = pd.merge(input_vuln_data.kev, input_vuln_data.epss, on='CVE', how='left')
df_kev_epss_nvd =  pd.merge(df_kev_epss, input_vuln_data.nvd, how="left", left_on='CVE', right_on='CVE')
df_kev_epss_nvd =  df_kev_epss_nvd[["CVE", "CVSS3", "EPSS", "EPSS Percentile", "date", "Description"]]

# exploitdbのデータフレームと結合
df = pd.merge(df_kev_epss_nvd, input_vuln_data.exploitdb, on="CVE", how="left")

# Group the dataframe by 'CVE' and create a poc column
grouped = df.groupby('CVE', sort=False)
poc_df = pd.DataFrame()

for name, group in grouped:
    poc_html = ""
    no_data_flag = True
    for item in group['PoC']:
        if type(item) is str:
            if no_data_flag: # Show poc button only if there is data
                poc_html += "<div><button class='poc-button'>Show poc</button><div class='poc' style='display: none;'>"
                no_data_flag = False
            poc_html += "<p><a href='" + str(item) + "' target='_blank'>" + str(item) + "</a></p>"
        else:
            poc_html += "<p></p>"
    if not no_data_flag:
        poc_html += "</div></div>"
    row = group.head(1).copy()
    row["PoC"] = poc_html
    poc_df = pd.concat([poc_df, row], ignore_index=True)

# 'date'で降順ソート
poc_df.sort_values(by='date', ascending=False, inplace=True)

# Convert the DataFrame to HTML and reset index starting from 1
poc_df.reset_index(drop=True, inplace=True)
poc_df.index += 1
table_html = poc_df.to_html(escape=False, index=True)

## Build html header and javascript
# For search and sort in UI
datatables_header = """
<link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.22/css/jquery.dataTables.min.css">
<script type="text/javascript" charset="utf8" src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
<script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.22/js/jquery.dataTables.min.js"></script>
"""
# Add JavaScript to toggle pocs when button is clicked
datatables_init = """\
<script>
$(document).ready(function() {
    var table = $('table').DataTable({
        'pageLength': 100
    });
    $(document).on('click', '.poc-button', function () {
        var pocDiv = this.nextSibling;
        if (pocDiv.style.display === "none") {
            pocDiv.style.display = "block";
        } else {
            pocDiv.style.display = "none";
        }
    });
});
</script>
"""

style = """
<style>
    table {
        border-collapse: collapse;
        width: 100%;
    }
    th, td {
        border: 1px solid #ddd;
        padding: 8px;
        text-align: left;
        font-size: 0.7em; 
    }
    tr:nth-child(even) {
        background-color: #f2f2f2;
    }
    th {
        padding-top: 12px;
        padding-bottom: 12px;
        text-align: left;
        background-color: #1e50a2;
        color: white;
    }
    h1 {
        color: #1e50a2;
        text-align: center;
    }
</style>
"""
# Add title and date to the HTML file
generated_date = "<p>Generated on: {}</p>\n".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
title = "<h1>KEV Tracker</h1>\n"
count_records = len(poc_df)
records_count_str = "<p>Number of Records: {}</p>\n".format(count_records)

# Create the HTML file
with open("index.html", "w") as f:
    f.write(style)
    f.write(title)
    f.write(records_count_str) 
    f.write(generated_date)
    f.write(datatables_header) 
    f.write(datatables_init)
    f.write(table_html)