# Got ChatGPT to make this code look nicer since I cannot publish the original version. It looked so bad lol :/

import os
import subprocess
import requests
import re
from bs4 import BeautifulSoup
import time

# Configuration
OUTPUT_DIR = "mcp_pentest_repos"
MAX_REPOS = 100  # Maximum repositories to clone
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")  # Optional: Set your GitHub token as env var (allows for a lot more requests per hour)
DEBUG = True  # Enable debug output
RATE_LIMIT_DELAY = 1  # Delay between requests to respect rate limits

headers = {}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    print("⚠️ No GitHub token found. You may hit rate limits when fetching repository details.")

def get_repo_info(repo_name):
    """Get repository details from GitHub API"""
    api_url = f"https://api.github.com/repos/{repo_name}"
    response = requests.get(api_url, headers=headers)
    if response.status_code != 200:
        print(f"Error fetching {repo_name}: {response.status_code}")
        return None
    
    return response.json()

def calculate_attack_surface(repo_data, repo_languages=None):
    """Calculate a rough attack surface score based on repo attributes"""
    score = 0
    
    # Popularity factors
    score += min(repo_data.get("stargazers_count", 0) / 100, 10)  # Cap at 10 points
    score += min(repo_data.get("forks_count", 0) / 20, 5)         # Cap at 5 points
    
    # Activity factors
    score += min(repo_data.get("open_issues_count", 0) / 10, 5)   # Cap at 5 points
    
    # Size factors
    score += min(repo_data.get("size", 0) / 1000, 5)              # Cap at 5 points
    
    # Language factors (score languages with higher potential for vulnerabilities)
    if repo_languages:
        if "JavaScript" in repo_languages or "TypeScript" in repo_languages:
            score += 5  # JS/TS often has more injection vulnerabilities
        if "Python" in repo_languages:
            score += 3  # Python can have command injection issues
        if "Java" in repo_languages or "C++" in repo_languages or "C" in repo_languages:
            score += 4  # Memory safety issues
        if "PHP" in repo_languages:
            score += 6  # PHP can have various injection issues
        if "Shell" in repo_languages:
            score += 6  # Shell scripts often have command injection vulnerabilities
    
    # If descriptions contain keywords indicating handling external data, APIs, etc.
    description = repo_data.get("description", "").lower()
    security_keywords = [
        "api", "oauth", "token", "auth", "cred", "shell", "exec", "file", "upload", 
        "command", "execute", "injection", "run", "process", "spawn", "cli", "terminal",
        "eval", "sandbox", "github", "aws", "azure", "gcp", "google", "sql", "database"
    ]
    for keyword in security_keywords:
        if keyword in description:
            score += 2
    
    # If name contains security-relevant terms
    name = repo_data.get("name", "").lower()
    for keyword in ["server", "mcp", "shell", "exec", "command", "run", "terminal", "cli"]:
        if keyword in name:
            score += 3
    
    return score

def clone_repo(repo_url, repo_name, output_dir):
    """Clone a repository to the local filesystem"""
    target_dir = os.path.join(output_dir, repo_name.split("/")[-1])
    
    try:
        subprocess.run(
            ["git", "clone", repo_url, target_dir], 
            check=True, 
            capture_output=True
        )
        print(f"Successfully cloned {repo_name} to {target_dir}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to clone {repo_name}: {e}")
        return False

def extract_repo_from_text(text):
    """Extract potential GitHub repository names from text"""
    # This pattern looks for user/repo format that GitHub uses
    matches = re.finditer(r'[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+', text)
    for match in matches:
        repo_name = match.group(0)
        # Check if this looks like a valid GitHub repo name
        if "/" in repo_name and not repo_name.startswith("/") and not repo_name.endswith("/"):
            # Exclude common non-repo patterns
            if not any(pattern in repo_name for pattern in [".com/", ".org/", ".io/", "example/"]):
                yield repo_name

def extract_repos_from_readme_content(readme_content):
    """Extract repository references from a README element"""
    repos = set()
    
    # Extract repositories from list items (server descriptions)
    list_items = readme_content.find_all(['li'])
    for item in list_items:
        item_text = item.get_text()
        # If an item has a GitHub link, it might describe a repository
        for repo in extract_repo_from_text(item_text):
            repos.add(repo)
        
        # Check for links within the list item
        for link in item.find_all('a', href=True):
            href = link['href']
            # Direct GitHub links
            match = re.search(r'github\.com/([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)', href)
            if match:
                repos.add(match.group(1))
                
    # Also extract from direct links in the README
    for link in readme_content.find_all('a', href=True):
        href = link['href']
        match = re.search(r'github\.com/([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)', href)
        if match:
            repos.add(match.group(1))
    
    return list(repos)

def get_all_repo_names_from_readme(html_content):
    """Extract all repository names from README regardless of HTML structure"""
    soup = BeautifulSoup(html_content, 'html.parser')
    repo_names = set()
    
    # Find all the list items
    list_items = soup.find_all('li')
    for item in list_items:
        # Extract text and try to find repo names
        text = item.get_text()
        repo_names.update(extract_repo_from_text(text))
        
    # Find all links
    links = soup.find_all('a', href=True)
    for link in links:
        href = link['href']
        # Check for GitHub repo links
        match = re.search(r'github\.com/([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)', href)
        if match:
            repo_names.add(match.group(1))
    
    # Find all code blocks that might contain repo references
    code_blocks = soup.find_all(['code', 'pre'])
    for code in code_blocks:
        text = code.get_text()
        repo_names.update(extract_repo_from_text(text))
        
    # Find all strong/bold text that might be repo names
    bold_texts = soup.find_all(['strong', 'b'])
    for bold in bold_texts:
        text = bold.get_text()
        if '/' in text and len(text.split('/')) == 2:
            repo_names.update(extract_repo_from_text(text))
    
    return repo_names

def scrape_mcp_servers_readme():
    """Scrape the MCP servers README to find all referenced repositories"""
    main_repo_url = "https://github.com/modelcontextprotocol/servers"
    response = requests.get(main_repo_url)
    
    if response.status_code != 200:
        print(f"Failed to fetch main repository: {response.status_code}")
        return []
    
    # Debug: Save HTML content to a file for inspection
    if DEBUG:
        with open("github_page.html", "w", encoding="utf-8") as f:
            f.write(response.text)
        print("Saved GitHub page HTML to github_page.html for inspection")
    
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Try different methods to find the README content
    readme_content = soup.find(id="readme")
    
    repos = []
    
    if not readme_content:
        print("Could not find README content with id='readme', trying alternative methods")
        
        # Try to find README section by other means
        article_content = soup.find('article')
        if article_content:
            print("Found <article> element, extracting repositories from it")
            repos = list(get_all_repo_names_from_readme(str(article_content)))
        
        # Try to find README by looking for markdown content
        markdown_content = soup.find(class_=lambda c: c and ('markdown' in c or 'readme' in c.lower()))
        if markdown_content:
            print(f"Found markdown content with class: {markdown_content.get('class')}")
            repos.extend(extract_repos_from_readme_content(markdown_content))
        
        # If we still don't have repos, try parsing the entire page
        if not repos:
            print("Extracting repositories from the entire page")
            repos = list(get_all_repo_names_from_readme(response.text))
    else:
        print("Found README content with id='readme'")
        repos = extract_repos_from_readme_content(readme_content)
    
    # Also add the main servers repository
    repos.append("modelcontextprotocol/servers")
    
    # Debug: print all found repository links before filtering
    if DEBUG:
        print(f"Found {len(repos)} repositories before filtering:")
        for repo in sorted(repos):
            print(f"  - {repo}")
    
    # Extract repository information from specific sections
    all_headers = soup.find_all(['h1', 'h2', 'h3'])
    for header in all_headers:
        if DEBUG:
            print(f"Found header: {header.get_text().strip()}")
        
        # If this is a section that might contain server info
        header_text = header.get_text().strip().lower()
        if any(term in header_text for term in ['server', 'reference', 'framework', 'resources']):
            # Find the next list after this header
            next_list = header.find_next('ul')
            if next_list:
                list_items = next_list.find_all('li')
                for item in list_items:
                    for repo in extract_repo_from_text(item.get_text()):
                        repos.append(repo)
    
    # Extract NPM packages that might be repository names
    npm_package_pattern = r'@modelcontextprotocol/([a-zA-Z0-9_.-]+)'
    npm_matches = re.finditer(npm_package_pattern, response.text)
    for match in npm_matches:
        package_name = match.group(1)
        if 'server' in package_name:
            repos.append(f"modelcontextprotocol/{package_name}")
    
    # Remove duplicates and filter out invalid repos
    unique_repos = []
    seen = set()
    for repo in repos:
        if repo.lower() not in seen and "/" in repo:
            # Basic validation - repos should have format "owner/name"
            parts = repo.split('/')
            if len(parts) == 2 and all(part for part in parts):
                unique_repos.append(repo)
                seen.add(repo.lower())
    
    return unique_repos

def main():
    print("🔍 Finding MCP server repositories...")
    repos = scrape_mcp_servers_readme()

    if not repos:
        print("❌ No repositories found. Please check your GitHub token and try again.")
        return
    
    print(f"\n📊 Found {len(repos)} repositories. Analyzing attack surfaces...")
    
    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Analyze and clone repositories
    analyzed_repos = []
    for repo_name in repos:
        # I just realised that function isn't defined and I don't remember what it was so uhhh
        is_valid_repo_name = lambda _: True
        try:
            if not is_valid_repo_name(repo_name):
                if DEBUG:
                    print(f"Skipping invalid repo name: {repo_name}")
                continue
                
            repo_data = get_repo_info(repo_name)
            if not repo_data:
                continue
                
            attack_score = calculate_attack_surface(repo_data)
            analyzed_repos.append((repo_name, attack_score, repo_data))
            
            if DEBUG:
                print(f"Analyzed {repo_name}: {attack_score:.1f}")
                
            # Respect rate limits
            time.sleep(RATE_LIMIT_DELAY)
            
        except Exception as e:
            if DEBUG:
                print(f"Error analyzing {repo_name}: {str(e)}")
            continue
    
    # Sort by attack surface score
    analyzed_repos.sort(key=lambda x: x[1], reverse=True)
    
    print("\n🎯 Top repositories by attack surface:")
    for repo_name, score, repo_data in analyzed_repos[:20]:  # Show top 20
        print(f"• {repo_name} - ⭐ {repo_data['stargazers_count']} - 🔓 Attack Score: {score:.1f}")
    
    print(f"\n📥 Cloning top {MAX_REPOS} repositories...")
    for repo_name, score, repo_data in analyzed_repos[:MAX_REPOS]:
        try:
            clone_repo(repo_data['clone_url'], repo_name, OUTPUT_DIR)
            print(f"✓ Cloned {repo_name}")
        except Exception as e:
            print(f"❌ Failed to clone {repo_name}: {str(e)}")
    
    print(f"\n✨ Summary:")
    print(f"• Analyzed: {len(analyzed_repos)} repositories")
    print(f"• Cloned: {min(MAX_REPOS, len(analyzed_repos))} repositories")
    print(f"• Output directory: {os.path.abspath(OUTPUT_DIR)}")

if __name__ == "__main__":
    main()