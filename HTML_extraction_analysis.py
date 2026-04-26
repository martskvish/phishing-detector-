#bs4 (BeautifulSoup) is a Python library used for web scraping and parsing HTML and XML documents. 
#requests is a Python library used for making HTTP requests.
import sqlite3
from bs4 import BeautifulSoup
import requests

def extraxt_html_content(url):
    #Send a GET request
    try:
        #Set a timeout to prevent the program from hanging indefiently if the website is unresponsive.
        response = requests.get(url, timeout=10)

        #Check if the request was unsuccessful.
        #If not return error.
        if response.status_code != 200:
            print(f"Failed to retrieve page. Status code:", response.status_code)
        return response
    except requests.exceptions.RequestException as error:
        print(f"connection error: {error}")
        return None

def extract_text_from_html(unfiltered):

    if unfiltered is None:
        return ""

    #Convert the raw HTML string into a structured, searchable tree object which is stored in filtered.
    filtered = BeautifulSoup(unfiltered.text, 'html.parser')

    #If the input is already a string, it will raise an AttributeError when trying to access the .text attribute.
    #Ecxept block catches this error 
    try:
        filtered = BeautifulSoup(unfiltered.text, 'html.parser')
    except AttributeError:
        filtered = BeautifulSoup(unfiltered, 'html.parser')

    #Filtered variable gets the HTML content from the response and parses it using BeautifulSoup.
    #Parsign means converting the HTML content into a structured format that allows for easy extraction of specific elements.
    
    #HTML Tags that contain visible text: <p> — paragraphs<h1> to <h6> — headings<li> — list items<div> — containers<blockquote> — quotes<pre> — preformatted text<dd>, <dt> — description lists
    valid_tags = ['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li', 'div', 'blockquote', 'pre', 'dd', 'dt']

    #Initalizes an empty string to store the extracted text.
    extracted_text = " "

    #Iterates repetively through all the specified valid tags in the parsed HTML content.
    #During each tag, it extracts the text content using get_text() method and appends it to the extracted_text string with a space in between for better readability.
    for tag in filtered.find_all(valid_tags):
        text = tag.get_text()
        if text:
            extracted_text += text + " "
    return extracted_text

def SQL_HTML_database_extraction():
   
    #Connects to a SQLite database named sus_keywords.db and creates a cursor object to interact with the database.
    connection = sqlite3.connect("DB/sus_keywords.db")
    cursor = connection.cursor() 

    cursor.execute("SELECT keyword, severity, weight FROM html_suspicious_phrases")
    html_phrases = cursor.fetchall()
    
    #Close the database connection to free up resources and keep data safe.
    connection.close()
    return html_phrases

def HTMLtext_analysis(HTML_text, keywords):

    #Convert the HTML text to lowercase to ensure case-insensitive matching.
    HTML_text = HTML_text.lower()
    
    #initilaize a score variable to keep track of the total score based on matched keywords and an empty list to store the matched keywords along with their severity and weight.
    score = 0
    matched_keywords = []


    #Iterates through each keyword, severity, and weight in the provided keywords list.
    #For each keyword, it checks if the keyword is present in the HTML text.
    for keyword, severity, weight in keywords:
        if keyword in HTML_text:

            #append the matched keyword along with its severity and weight to the matched_keywords list.
            matched_keywords.append((keyword, severity, weight))

            #adds the weight of the matched keyword to the total score.
            score = score + weight

    return score, matched_keywords

def HTML_tag_analyser(HTML_raw, full_domain): 

    #Only get SLD (second level domain) 
    parts = full_domain.split(".")
    domain = parts[-2]
    
    #Convert the raw HTML string into a structured, searchable tree object which is stored in filtered.
    #Explain how parsing works. 
    filtered = BeautifulSoup(HTML_raw.text, 'html.parser')

    #Initialise score and matched_tags variable
    score = 0
    matched_tags = []

    #Iterates through all the form tags in the parsed HTML.
    #Gets the value of the action attribute of the form tag. The action attribute specifies where the form data should be sent when the form is submitted.
    #If actiontio attribute exists and does not contain the domain of URL being analysed and it starts with "http", it is considered suspicious because it indicates that the form is submitting data to an external site.
    #Example - <form action="https://evil.com/steal-data">
    for form in filtered.find_all('form'):
        action = form.get('action', '')
        if action and domain not in action and action.startswith('http'):
            score = score + 20
            matched_tags.append(('form', action))

    #Iterates through all the script tags in the parsed HTML.
    #Get value of src attribute of the script tag. The src attribute specifies the URL of an external script file.        
    #Example - <script src="https://evil.com/keylogger.js"></script>
    for script in filtered.find_all('script'):
        src = script.get('src', '')
        if src and domain not in src and src.startswith('http'):
            score = score + 15
            matched_tags.append(('script', src))
    
    #Iterates through all the iframe tags in the parsed HTML.
    #Iframes are tool for including a cloned legitimate page (a real bank login) inside a phishing website.
    #Get value of isrc attribute of the iframe tag. The isrc attribute specifies the URL of an external iframe content.
    #Example - <iframe src="https://evil.com/fake-barclays-login"></iframe>
    for iframe in filtered.find_all('iframe'):
        isrc = iframe.get('src', '')
        if isrc and domain not in isrc:
            score  = score + 12
            matched_tags.append(('iframe', isrc))


    #Iterates through all the base tags in the parsed HTML.
    #base tag sets default URL for all link on page. if base tag points to external website, it can be used to send password from login form to the attacker's server instead of the real bank.
    #Get value of href attribute of the base tag.
    #Example - <base href="https://evil.com/">       
    for base in filtered.find_all('base'):
        href = base.get('href', '')
        if href and domain not in href and href.startswith('http'):
            score = score + 18
            matched_tags.append(('base', href))


    #Meta tag with http-equiv="refresh" can be used to automatically redirect users to another page after a certain amount of time. 
    #If the content attribute of meta tag doesnt contain the domain of the URL being analysed, it may be considered that the page is trying to redirect users to an external site.
    #Example - <meta http-equiv="refresh" content="0; url=https://evil.com/fake-login">
    for meta in filtered.find_all('meta'):
        http_eq = meta.get('http-equiv', '')
        content = meta.get('content', '')
        if http_eq.lower() == 'refresh' and domain not in content:
            score = score + 12 
            matched_tags.append(('Auto redirect meta refresh', 'High', 12))
    

    #Iterates through all the anchor tags in the parsed HTML.
    #Get value of href attribute of the anchor tag. The href attribute specifies the URL of the link.
    #if the href attribute contains the domain of the URL being analysed, it is considered a legitimate link.
    #example - <a href="/privacy-policy">Privacy Policy</a>
    for base2 in filtered.find_all('a'):
        href = base2.get('href', '')
        text = base2.get_text().lower()
        if 'privacy' in text:
            if domain in href:
                score = score - 5
                matched_tags.append(('Privacy link', 'Low', -5))
            else:
                score = score + 5
                matched_tags.append(('Suspicious privacy link', 'High', 5))
        

    return score, matched_tags


def HTML_code_jaccard(HTML_raw, simmilar, levenshteins_distance_domain):

    #optimisation (only run heavy checks when needed)
    if levenshteins_distance_domain >= 1 and levenshteins_distance_domain <= 4:  
        
        jaccard_similarity = 0.0
        reasson = ""
        score = 0 

        #Convert raw HTML code into structured, searchable tree.
        filtered1 = BeautifulSoup(HTML_raw.text, 'html.parser')
        filtered2 = BeautifulSoup(simmilar.text, 'html.parser')

        #Remove script and style tags and their content from the parsed HTML. 
        #These tags often contain code that is not visible to users but can be used for malicious purposes.
        #Allows us to focuse on the vissible conent on web page.
        for tag in filtered1(["script", "style"]):
            tag.decompose()
        for tag in filtered2(["script", "style"]):
            tag.decompose()

        #Extract the visible text from the both filtered HTML and convert it to lowercase for better comparison.
        #Split the extracted text into individual words and set to set.
        html_text = filtered1.get_text(separator=" ").lower()
        words1 = set(html_text.split())

        html_text2 = filtered2.get_text(separator=" ").lower()
        words2 = set(html_text2.split())    

        #Intersection of two sets
        intersection = len(words1.intersection(words2))
        #Unions of two sets
        union = len(words1.union(words2))

        #Calculate Jaccard similarity as the size of the intersection divided by the size of the union of the two sets of words.
        #If the union is zero, it means both sets are empty and the similarity is defined as 0.0 to avoid division by zero error.
        if union == 0:
            jaccard_similarity = 0.0 
        else:
            jaccard_similarity = intersection / union 
        
        if jaccard_similarity > 0.8:
            reasson = "Very high similarity to known site (possible clone)"
            score = 30
        elif jaccard_similarity > 0.5:
            reasson = "Moderate similarity detected"
            score = 15
        elif jaccard_similarity > 0.2:
            reasson = "Low similarity"
            score = 5
        else:
            reasson = "No significant similarity"
            score = 0
    
    else:
        jaccard_similarity = 0.0
        reasson = "Domain name eithersame or not similar enough to known sites for HTML comparison to be meaningful"
        score = 0 

        return jaccard_similarity, reasson, score
    return jaccard_similarity, reasson, score