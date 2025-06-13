import os
import re
import yara

def combine_yar_files(directory, output_file):
    # Regex to find rule blocks in YARA files
    rule_pattern = re.compile(r'rule\s+(\w+)\s*{([^}]*)}', re.DOTALL)
    
    # Track valid rule names and their content
    rule_data = {}
    
    # Scan directory and subdirectories
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.yar'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        # Find all rules in the file
                        rules = rule_pattern.finditer(content)
                        for rule in rules:
                            rule_name = rule.group(1)
                            rule_content = rule.group(0)  # Entire rule including name and body
                            # Attempt to compile the rule to check syntax
                            try:
                                yara.compile(source=rule_content)
                                if rule_name not in rule_data:
                                    rule_data[rule_name] = rule_content
                                else:
                                    print(f"Excluded duplicate rule '{rule_name}' from {file_path}")
                            except yara.SyntaxError as e:
                                print(f"Skipped invalid rule '{rule_name}' from {file_path}: {e}")
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
    
    # Write combined content to output file
    if rule_data:
        with open(output_file, 'w') as f:
            f.write('\n\n'.join(rule_data.values()))
        print(f"Combined rules written to {output_file}")
    else:
        print("No valid .yar files found to combine.")

# Example usage
combine_yar_files('C:/Users/jay-delapena/Desktop/Projects/YARA_Rules/', 'combined_yara_rules.yar')