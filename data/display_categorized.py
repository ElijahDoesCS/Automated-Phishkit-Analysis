import pandas as pd
import matplotlib.pyplot as plt

# Data
data = [
    ("3D and CAD Files", ".obj", 1),
    ("Audio Files", ".mp3", 5),
    ("Audio Files", ".wav", 4),
    ("Audio Files", ".ogg", 2),
    ("Backup and Temporary Files", ".dist", 9),
    ("Backup and Temporary Files", ".bak", 5),
    ("Compressed Files", ".gz", 77),
    ("Compressed Files", ".zip", 16),
    ("Compressed Files", ".rar", 1),
    ("Configuration Files", ".xml", 115),
    ("Configuration Files", ".json", 75),
    ("Configuration Files", ".config", 39),
    ("Configuration Files", ".yml", 35),
    ("Configuration Files", ".lock", 12),
    ("Configuration Files", ".conf", 5),
    ("Configuration Files", ".cfg", 4),
    ("Configuration Files", ".yaml", 4),
    ("Configuration Files", ".env", 2),
    ("Database Files", ".sql", 48),
    ("Database Files", ".db", 10),
    ("Database Files", ".sqlite", 4),
    ("Database Files", ".mmdb", 2),
    ("Design Files", ".graffle", 1),
    ("Design Files", ".psd", 1),
    ("Design Files", ".sketch", 1),
    ("Executable Files", ".exe", 8),
    ("Executable Files", ".bin", 3),
    ("Executable Files", ".apk", 1),
    ("Font Files", ".woff", 117),
    ("Font Files", ".ttf", 112),
    ("Font Files", ".eot", 108),
    ("Font Files", ".otf", 55),
    ("Font Files", ".woff2", 48),
    ("Image Files", ".png", 225),
    ("Image Files", ".gif", 159),
    ("Image Files", ".svg", 145),
    ("Image Files", ".jpg", 131),
    ("Image Files", ".ico", 52),
    ("Image Files", ".jpeg", 12),
    ("Image Files", ".webp", 2),
    ("Image Files", ".jfif", 1),
    ("Image Files", ".tiff", 1),
    ("Project and Package Files", ".jar", 3),
    ("Project and Package Files", ".suo", 3),
    ("Project and Package Files", ".gradle", 2),
    ("Project and Package Files", ".idx", 2),
    ("Project and Package Files", ".iml", 2),
    ("Project and Package Files", ".pack", 2),
    ("Project and Package Files", ".vcproj", 1),
    ("Scripting Files", ".php", 238),
    ("Scripting Files", ".vbs", 68),
    ("Scripting Files", ".sh", 26),
    ("Scripting Files", ".c", 20),
    ("Scripting Files", ".h", 20),
    ("Scripting Files", ".py", 11),
    ("Scripting Files", ".bat", 9),
    ("Scripting Files", ".rb", 6),
    ("Scripting Files", ".cpp", 4),
    ("Scripting Files", ".cs", 3),
    ("Scripting Files", ".java", 3),
    ("Scripting Files", ".m", 3),
    ("Scripting Files", ".groovy", 2),
    ("Scripting Files", ".coffee", 1),
    ("Scripting Files", ".hpp", 1),
    ("Scripting Files", ".pl", 1),
    ("Shared Libraries", ".dll", 6),
    ("Shared Libraries", ".so", 3),
    ("Spreadsheet Files", ".xls", 1),
    ("Spreadsheet Files", ".xlsx", 1),
    ("System and Security Files", ".htaccess", 110),
    ("System and Security Files", ".crt", 81),
    ("System and Security Files", ".pem", 11),
    ("System and Security Files", ".asc", 4),
    ("System and Security Files", ".key", 3),
    ("Text and Document Files", ".html", 192),
    ("Text and Document Files", ".txt", 191),
    ("Text and Document Files", ".pdf", 147),
    ("Text and Document Files", ".md", 111),
    ("Text and Document Files", ".ini", 14),
    ("Text and Document Files", ".log", 10),
    ("Text and Document Files", ".csv", 7),
    ("Text and Document Files", ".po", 7),
    ("Text and Document Files", ".plist", 5),
    ("Text and Document Files", ".rst", 5),
    ("Text and Document Files", ".rtf", 4),
    ("Text and Document Files", ".dox", 3),
    ("Text and Document Files", ".mdown", 1),
    ("Version Control Files", ".gitignore", 35),
    ("Version Control Files", ".gitattributes", 13),
    ("Version Control Files", ".gitkeep", 5),
    ("Version Control Files", ".git", 2),
    ("Version Control Files", ".gitmodules", 1),
    ("Video Files", ".swf", 68),
    ("Video Files", ".mp4", 7),
    ("Web Development Files", ".css", 202),
    ("Web Development Files", ".js", 180),
    ("Web Development Files", ".scss", 87),
    ("Web Development Files", ".map", 20),
    ("Web Development Files", ".vue", 3)
]

# Create a DataFrame
df = pd.DataFrame(data, columns=["Category", "File Extension", "Count"])

# Group by Category and sum the counts
category_counts = df.groupby("Category")["Count"].sum()

# Plot the bar graph
category_counts.plot(kind='bar', color='skyblue', edgecolor='black')

# Customize the plot
plt.title('File Counts by Category')
plt.xlabel('Category')
plt.ylabel('Total Count')
plt.xticks(rotation=90)  # Rotate category names for better readability
plt.tight_layout()

# Show the plot
plt.show()

