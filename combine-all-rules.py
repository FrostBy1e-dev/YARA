import os
import re

def combine_yar_files(directory, output_file):
    # Regex to find rule names in YARA files
    rule_name_pattern = re.compile(r'rule\s+(\w+)\s*{')
    
    # Track rule names and their files
    rule_files = {}
    
    # Store all file contents
    all_rules = []
    
    # Scan directory and subdirectories
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.yar'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        all_rules.append(content)
                        
                        # Extract rule names
                        rule_names = rule_name_pattern.findall(content)
                        for name in rule_names:
                            if name in rule_files:
                                rule_files[name].append(file_path)
                            else:
                                rule_files[name] = [file_path]
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
    
    # Warn about duplicate rule names
    duplicates = {name: files for name, files in rule_files.items() if len(files) > 1}
    if duplicates:
        print("Warning: Duplicate rule names found:")
        for name, files in duplicates.items():
            print(f"Rule '{name}' appears in: {', '.join(files)}")
        print("You may need to rename these rules in the combined file.")
    
    # Write combined content to output file
    if all_rules:
        with open(output_file, 'w') as f:
            f.write('\n\n'.join(all_rules))
        print(f"Combined rules written to {output_file}")
    else:
        print("No .yar files found to combine.")

# Example usage
combine_yar_files('C:/Users/jay-delapena/Desktop/Projects/YARA_Rules/', 'combined_yara_rules.yar')