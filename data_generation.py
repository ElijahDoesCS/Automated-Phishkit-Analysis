import os
import zipfile
import random
import re
from collections import defaultdict
import csv

from difflib import SequenceMatcher

# Root directory where all sample kits are stored
folder_path = '../phishing/phishing_kits/0xkzip'

file_extension_taxonomy = {
    "Text and Document Files": {".docx", ".pdf", ".rtf", ".md", ".rst", ".csv", ".log", ".po", ".mdown", ".dox", ".ini", ".txt", ".html", ".plist", ".readme"},
    "Image Files": {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".jfif", ".cur", ".webp", ".tiff"},
    "Audio Files": {".mp3", ".wav", ".aac", ".ogg"},
    "Video Files": {".mp4", ".avi", ".mov", ".swf"},
    "Executable Files": {".exe", ".apk", ".apks", ".bin"},
    "Compressed Files": {".zip", ".tar", ".rar", ".gz", ".7z", ".squashfs"},
    "Web Development Files": {".css", ".js", ".scss", ".map", ".vue"},
    "Scripting Files": {".py", ".php", ".sh", ".bat", ".vbs", ".pl", ".awk", ".groovy", ".coffee", ".rb", ".kt", ".c", ".cpp", ".java", ".cs", ".m", ".hpp", ".h"},
    "Database Files": {".sqlite", ".db", ".mdb", ".sql", ".mmdb"},
    "Configuration Files": {".json", ".xml", ".yaml", ".yml", ".config", ".conf", ".cfg", ".lock", ".env"},
    "Font Files": {".woff", ".woff2", ".ttf", ".eot", ".otf"},
    "System and Security Files": {".crt", ".pem", ".p12", ".key", ".p8", ".htaccess", ".htpasswd", ".cer", ".asc"},
    "Backup and Temporary Files": {".bak", ".tmp", ".old", ".dist"},
    "Project and Package Files": {".jar", ".iml", ".gradle", ".pack", ".idx", ".suo", ".vcproj", ".proj", ".pom"},
    "Version Control Files": {".gitignore", ".gitattributes", ".gitmodules", ".gitkeep", ".hgignore", ".git"},
    "Spreadsheet Files": {".xls", ".xlsx", ".xlsm"},
    "3D and CAD Files": {".obj", ".fbx", ".stl"},
    "Design Files": {".ai", ".psd", ".sketch", ".xd", ".graffle"},
    "Shared Libraries": {".so", ".dll"},
}

class KitStats:
    def __init__(self, zip_directory, file_count, total_size_kb, unique_file_types_count, generalized_file_types):
        self.zip_directory = zip_directory
        self.file_count = file_count  # Total number of files (non-directories)
        self.total_size_kb = total_size_kb  # Total size of the zip file in kilobytes
        self.unique_file_types_count = unique_file_types_count  # Count of unique file types
        self.generalized_file_types = generalized_file_types  # Dictionary of generalized file types

    def __repr__(self):
        # Provide a string representation for easy printing
        return f"KitStats(zip_directory={self.zip_directory} file_count={self.file_count}, total_size_kb={self.total_size_kb}, " \
               f"unique_file_types_count={self.unique_file_types_count}, generalized_file_types={self.generalized_file_types})"

# Function to find the common root path of a file
def get_common_root_path(extension_path, depth=2):
    parts = extension_path.split('/')
    if len(parts) >= depth:
        return '/'.join(parts[:depth])
    return extension_path

def get_valid_zip_files(zip_files):
        """Filter out corrupt or empty zip files."""
        valid_kits = []

        class BadZipFileError(Exception):
            """Custom exception raised when a zip file has zero files or is invalid."""
            pass

        for zip_path in zip_files:
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    # Get a list of files in the archive excluding directories
                    file_paths = [file for file in zf.namelist() if not file.endswith('/')]
                    file_count = len(file_paths)

                    if file_count == 0:
                        # Raise custom exception if there are no files in the zip archive
                        raise BadZipFileError(f"Zip file {zip_path} contains no files.")
                    else:
                        valid_kits.append(zip_path)

            except zipfile.BadZipFile:
                print(f"Corrupt ZIP file: {zip_path}")
            except BadZipFileError as e:
                print(e)

        return valid_kits

def analyze_kit(zip_file_path):
    # Add a try-except block to handle invalid zip files
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
            # List all file names in the zip archive
            file_list = zip_file.namelist()

            # Filter out directories (directory names end with '/')
            file_paths = [file for file in file_list if not file.endswith('/')]

            # Count total number of files (non-directories)
            file_count = len(file_paths)

            # Calculate aggregate file sizes in bytes
            total_size = sum(info.file_size for info in zip_file.infolist())

            # Find unique file types by examining file extensions (ignoring directories)
            file_types = {file.split('.')[-1] for file in file_paths if '.' in file}  # Ensure it’s a file with an extension

            # Dictionary to map root paths to their unique file types
            generalized_file_types = defaultdict(set)

            # Generalize root paths for wildcard dynamic types
            for file_extension in file_types:
                # Root path or default extension
                root_path = get_common_root_path(file_extension)

                # Only add the file extension if it’s not already associated with the root path
                if file_extension not in generalized_file_types[root_path]:
                    generalized_file_types[root_path].add(file_extension)

            # Optional: Convert the defaultdict to a regular dict for easier viewing
            generalized_file_types = dict(generalized_file_types) 

            # Create and return a KitStats object with the data
            return KitStats(zip_file_path, file_count, total_size / 1000, len(file_types), generalized_file_types)

    except zipfile.BadZipFile:
        print(f"Error: {zip_file_path} is not a valid zip file.")
        return None

def generate_metadata(sampled_kits, csv_directory):

    # Ensure the zip files are valid
    sampled_kits = get_valid_zip_files(sampled_kits)

    sampled_kits_stats = []
    for kit in sampled_kits:

        stats = analyze_kit(kit)
        if stats:  # Only print stats if they exist (i.e., if the file is a valid zip)
            print("DIRECTORY: ", stats.zip_directory) # Initial zip directory we are analyzing
            print("Number of directory leaves: ", stats.file_count)  # Access the file count
            print("Size of zip file: ", stats.total_size_kb)  # Access the total size in kilobytes
            print("Number of unique file types: ", stats.unique_file_types_count)  # Access the unique file types count
            print("Enumeration of file extensions (2 deep parent directories for wildcards)\n", list(stats.generalized_file_types.keys()))  # Access the generalized file types dictionary
            
            # Append to the array of associated stats objects
            sampled_kits_stats.append(stats)

    # Calculate and export file counts
    def classify_file_extensions(all_zip_stats):
        file_extension_counts = {category: defaultdict(int) for category in file_extension_taxonomy.keys()}
        uncategorized_extensions = defaultdict(int)

        for zip_stats in all_zip_stats:
            for file_extension in zip_stats.generalized_file_types:
                # Normalize the extension for comparison
                normalized_extension = f".{file_extension.strip().lower()}"  # Ensure consistent formatting
                matched = False

                # Look for the normalized extension in the taxonomy
                for category, extensions in file_extension_taxonomy.items():
                    if normalized_extension in extensions:
                        file_extension_counts[category][normalized_extension] += 1
                        matched = True
                        break
                
                # If no match found, add to uncategorized
                if not matched:
                    uncategorized_extensions[normalized_extension] += 1

        return file_extension_counts, uncategorized_extensions
    
    taxonomy_counts, misc_and_dynamic_extensions = classify_file_extensions(sampled_kits_stats)

    def ensure_directory_exists(directory):
        """Ensure the specified directory exists, creating it if necessary."""
        if not os.path.exists(directory):
            os.makedirs(directory)

    def export_taxonomy(taxonomy_counts, directory):
        """Export the categorized counts to a CSV file."""
        ensure_directory_exists(directory)
        
        file_path = os.path.join(directory, "categorized_file_counts.csv")
        
        with open(file_path, mode="w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            # Write the header
            writer.writerow(["Category", "File Extension", "Count"])
            
            # Write the data
            for category, extensions in sorted(taxonomy_counts.items()):
                for ext, count in sorted(extensions.items(), key=lambda x: (-x[1], x[0])):  # Sort by count (desc) then alphabetically
                    writer.writerow([category, ext, count])
        
        # print(f"Categorized file counts exported to: {file_path}")

    def export_uncategorized(uncategorized_extensions, directory):
        """Export the uncategorized extensions to a CSV file."""
        ensure_directory_exists(directory)
        
        file_path = os.path.join(directory, "uncategorized_file_extensions.csv")
        
        with open(file_path, mode="w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            # Write the header
            writer.writerow(["File Extension", "Count"])
            
            # Write the data
            for ext, count in sorted(uncategorized_extensions.items(), key=lambda x: (-x[1], x[0])):  # Sort by count (desc) then alphabetically
                writer.writerow([ext, count])
        
        # print(f"Uncategorized file extensions exported to: {file_path}")
    export_taxonomy(taxonomy_counts, csv_directory)
    export_uncategorized(misc_and_dynamic_extensions, csv_directory)

    def analyze_kit_distributions(sampled_kits_stats, output_dir = csv_directory[2:]):
         # Define more granular bins for file count
        file_count_bins = [0, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 3000, 5000, 10000, 20000]
        file_count_labels = [f"{file_count_bins[i]}-{file_count_bins[i+1]-1}" for i in range(len(file_count_bins) - 1)] + ["20000+"]
        file_count_distribution = {label: 0 for label in file_count_labels}

        unique_file_types_bins = [1, 5, 10, 20, 50, 100, 200]
        unique_file_types_labels = [f"{unique_file_types_bins[i]}-{unique_file_types_bins[i+1]-1}" for i in range(len(unique_file_types_bins) - 1)] + ["200+"]
        unique_file_types_distribution = {label: 0 for label in unique_file_types_labels}

        # Zip size (KB) - logarithmic binning
        zip_size_bins = [0, 5, 10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000, 500000]
        zip_size_labels = [f"{zip_size_bins[i]}-{zip_size_bins[i+1]-1}" for i in range(len(zip_size_bins) - 1)] + ["500000+"]
        zip_size_distribution = {label: 0 for label in zip_size_labels}

        # Iterate through each kit's stats and categorize by all three metrics
        for kit in sampled_kits_stats:
            file_count = kit.file_count
            unique_file_types = kit.unique_file_types_count
            zip_size = kit.total_size_kb

            # File Count Distribution
            for i in range(len(file_count_bins) - 1):
                if file_count_bins[i] <= file_count < file_count_bins[i + 1]:
                    file_count_distribution[file_count_labels[i]] += 1
                    break
            if file_count >= file_count_bins[-1]:
                file_count_distribution["20000+"] += 1

            # Unique File Types Distribution
            for i in range(len(unique_file_types_bins) - 1):
                if unique_file_types_bins[i] <= unique_file_types < unique_file_types_bins[i + 1]:
                    unique_file_types_distribution[unique_file_types_labels[i]] += 1
                    break
            if unique_file_types >= unique_file_types_bins[-1]:
                unique_file_types_distribution["200+"] += 1

            # Zip Size Distribution
            for i in range(len(zip_size_bins) - 1):
                if zip_size_bins[i] <= zip_size < zip_size_bins[i + 1]:
                    zip_size_distribution[zip_size_labels[i]] += 1
                    break
            if zip_size >= zip_size_bins[-1]:
                zip_size_distribution["500000+"] += 1
                # print(zip_size)

        # Print distributions to the terminal
        # Write distributions to CSV files
        def write_csv(data_dict, filename):
            with open(os.path.join(output_dir, filename), mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Range", "Count"])
                writer.writerows(data_dict.items())

        write_csv(file_count_distribution, "file_count_distribution.csv")
        write_csv(unique_file_types_distribution, "unique_file_types_distribution.csv")
        write_csv(zip_size_distribution, "zip_size_distribution.csv")

        # print(f"Distributions saved in directory: {output_dir}")

    # Example usage
    analyze_kit_distributions(sampled_kits_stats)

    return

def random_sample(folder_path, sample_size):
    # Collect all .zip files in the directory
    zip_files = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith('.zip'):
                zip_files.append(file_path)
            else:
                print(f"File does not end with .zip: {file_path}")

     
    # Take a random sample of sample_size zip files
    return random.sample(zip_files, min(sample_size, len(zip_files)))

# Metadata for control
generate_metadata(random_sample(folder_path, 500), "./control")

# Categorize based on pre-compromisation and collect metadata on each sample set
def categorized_metadata_analysis(folder_path, sample_size):

    # Collect all .zip files in the directory
    zip_files = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith('.zip'):
                zip_files.append(file_path)
            else:
                print(f"File does not end with .zip: {file_path}")

    # Take a random sample of sample_size zip files
    sampled_kits = random.sample(zip_files, min(sample_size * 2, len(zip_files)))
    
    sampled_kits = get_valid_zip_files(sampled_kits)
    
    # # Categorize the kits by their file contents
    sampled_kits_dynamic = []
    sampled_kits_target = []

    def similar(a, b):
        """Calculate the similarity ratio between two strings using SequenceMatcher."""
        return SequenceMatcher(None, a, b).ratio()

    def perform_categorization(sampled_kits_dynamic, sampled_kits_target, sampled_kits):
        """Categorize phishing kits based on their file contents."""
        for kit_path in sampled_kits:
            try:
                with zipfile.ZipFile(kit_path, 'r') as zf:
                    # Extract all files for inspection
                    file_contents = {file: zf.read(file).decode(errors='ignore') for file in zf.namelist() if not file.endswith('/')}
                    
                    precompromised_score = 0
                    dynamic_score = 0

                    """Categorize phishing kits based on their file contents."""
                    high_risk_domains = [
                        "amazon", "british gas", "citi bank", "google", "netflix", "godaddy", "adobe", "alaska bank", 
                        "alibaba", "apple", "aws", "bank of america", "capitalone", "chase", "citibank", "citizen bank", 
                        "coin base", "comcast", "dropbox", "ebay", "excel", "facebook", "instagram", "first horizon", 
                        "hotmail", "keybank", "linkedin", "meritrust", "microsoft", "msoffice", "navyfederal", "onedrive", 
                        "paypal", "quickbook", "usps", "wells fargo", "yahoo"
                    ]
                    
                    # Check each file's contents
                    for file_name, content in file_contents.items():
                        # Check for url in general
                        if "http://" in content or "https://" in content:
                                    precompromised_score += 0.5 
                        # Check for exitlink in php files
                        if file_name.endswith('.php') and "$exitlink" in content.lower():
                            precompromised_score += 1    

                        # PROBLEM ABOUT PROCESSING FOR SIMILARITY IN OVERLAPPING BLOCKS
                        def similarity_in_content(domain, file_content):
                            return 0
                        def similarity_in_file_name(domain, name):
                            return 0

                        # Check for URL targeting based on known legit URLs
                        for domain in high_risk_domains:                                 
                            # Check for partial matches in the content
                            precompromised_score += similarity_in_content(domain, content.lower())  # Arbitrarily scored 
                            precompromised_score += similarity_in_file_name(domain, file_name)

                        # Check for dynamic session file structure in directory structure & file content

                        # Check for dynamic domain generation patterns (dynamic score)
                        if any(keyword in content for keyword in ["Math.random", "random", "concat", "+", "new URL"]):
                            dynamic_score += 1  # Pattern for dynamic URL generation found
                        

                     # Categorize the kit based on the score
                    if precompromised_score > dynamic_score:
                        sampled_kits_target.append(kit_path)  # Likely a pre-compromised domain phishing kit
                    elif dynamic_score > precompromised_score:
                        sampled_kits_dynamic.append(kit_path)  # Likely a dynamic domain generation phishing kit

            except Exception as e:
                print(f"Error processing {kit_path}: {e}")
        
        return sampled_kits_dynamic, sampled_kits_target

    # sampled_kits_dynamic, sampled_kits_target = perform_categorization(sampled_kits_dynamic, sampled_kits_target, sampled_kits)

    # def sample_kits(sampled_kits):
    #     sampled_kits_stats = []
    #     for kit in sampled_kits:

    #         stats = analyze_kit(kit)
    #         if stats:  # Only print stats if they exist (i.e., if the file is a valid zip)

    #             # Append to the array of associated stats objects
    #             sampled_kits_stats.append(stats)

    #     return sampled_kits_stats    
    
    # return [sample_kits(sampled_kits_dynamic), sample_kits(sampled_kits_target)]

dynamic_generation_zip_files, targeted_attack_zip_files = categorized_metadata_analysis(folder_path, 500) 
generate_metadata(dynamic_generation_zip_files)
generate_metadata(targeted_attack_zip_files)