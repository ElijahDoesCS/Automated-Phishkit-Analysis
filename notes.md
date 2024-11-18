# Notes for creating automated analysis

### Elaborating on slides notes for script agenda
- Most kits are designed for specific domains:
    - Amazon
    - Netflix
- Img, png, ico files mimic domains
    - Dynamically load images that replicate logos, buttons, and icons from legitimate sites
    - Copy assets directly from sites
    - .ico files
        - favicons that mimic the browser tab
    - .png & .img files
        - Login instructions or prompts
        - Avoid detection by text crawlers
    - Lazy load images from external URLs
- File naming structure to mimic legit file paths
    - Make the directory structure mimic that of the legitamate applications they are impersonating
    - Mimic file structure through extension mimicking
    - Random or dynamic elements in file paths to avoid deteection and caching by security tools
- Randomized session IDs
    - Phishkit generates a unique session ID for each visitor
    - Generates unique file structure and paths based on this session ID
- Dynamic page design occurs with kits stripping domain from email to dynamically craft website based on where a user was linked
    - Send an email to a user
    - List link in email that contains the email address
    - Based on the email address that clicked the link, the phishing site can dynamically generate the page in a tailored manner
- They are 
    1. appending random strings
    2. dynamically generating content based on domain, containing both email address routes and session IDs
        - May be discarding session IDs after login compromisation?
    3. Offering free hosting services for new phishing sites
    4. Obfuscating kit source code using data hiding
- Anticipated challenges
    - Difficulty in automating across drastically different phishkits
    - Obfuscation within kit source code
        - Data hiding within .img files

### Elaborating on progress report deliverables
1. What are the comon domain/URL manipulation methods in phishing kits 
2. How effective are static and automated analyses in identifying these methods?
3. Can these analyses improve the speed and accuracy of phishing attack termination?

- Current classification of URLs 
        - Types of attacks each URL was designed for
- Utilize free hosting combined with various URL generation methods i.e. 
    - Similar but altered (Amazzon)
- Familiy of attacks associated w/ phish-kits
    - Vary based upon phishkit use case
- 90% of code is shared across the entire dataset
- Security vulnerabilities that exist within phishkits
    - Backdoors
    #### Two distinct groups based on functionality
    - Specific domain targets
        - Appending endpoints to pre-compromised URLs
        - Using legitimate looking file structure
            - Legitamate looking file structure
                - Mimic legitamate domains
                - Launch on preexisting root domains
        - Redirect to legit domain
            - Flow:
                - Host on compromised domain or dynamically generated one
                - Steal information, redirect to legit domain 
            - Generate a random 3 digit number, append it to the domain name, create a parent directory with this string, recursively copying files to new parent directory
    - Dynamic Multi-Domain
            - Anti Evasion
            - Dynamically target multiple domains
            - Create anti-evasion abilities independent of the attack domain
                - Domain scraping from a victim's email
                    - Display error
                        - Prompt victims to enter credentials to continue
                        - Send back to referring domain
                    - Enables users to circumnavigate hard-coded domains
                - Generating randomized character strings that is appended to the index.html
                    - Impersonating user session IDs
                        - Mimic authentication routines
                - Partial randomization = blacklisting evasion

# Rigorous automation plan
## Generating automated analyses for detecting the frequency and distribution of the functions found in static analyses
- Go into each kit and detect likely parent kit
- Go into each kit and track variance in file structure, size, languages, etc.
- Go into each kit and classify them as most likely being pre-compromised kits or dynamic kits
    - Develop a range of distribution
- Perform a survey in which we compel users to look for items through links

### Enumerate these funcitonalities and their association with each kit type
- Develop code to extract such kits using regular expression analyses
- Possibly analyze frequency of obfuscation techniques, file structure and languages to quantify variance in explaining study struggles

## Details of script functionality
### General Automation Method
    - Work across kit infrastructures
        - Languages
        - File structure
        - File extensions
        - Group similar domain manipulation techniques
            - Purpose 
            - Effectiveness
