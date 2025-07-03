import json
import os
import re
import chardet
import subprocess
import uuid
from requests.auth import HTTPBasicAuth
from bs4 import BeautifulSoup
from atlassian import Confluence
import requests
from bs4 import NavigableString
from dotenv import load_dotenv
import binascii
from Crypto.Hash import SHA256, HMAC
import random
import string

load_dotenv()
images_folder = "images"
space_key=os.getenv("space_key")
shared_paragraph_space_key=os.getenv("shared_paragraph_space_key")
image_hub_space_key=os.getenv("image_hub_space_key")
conf_doc_page=os.getenv("Base_url")
tooltip_space_key=os.getenv("tooltip_space_key")
#credentials for authentication
BASE_URL = "https://rest.opt.knoiq.co/api/v1"
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")
SITE_ID = os.getenv("SITE_ID") 
USER_TYPE = "Admin" 
SECRET_KEY = os.getenv("SECRET_KEY")
knosys_crt=os.getenv("crt_path")
print(knosys_crt,"Knosys cert here")
Conf_crt=os.getenv("confluence_crt")
img_space_id=os.getenv("img_space_id")
image_hub_space_key=os.getenv("image_hub_space_key")
shared_paragraph_space_key=os.getenv("shared_paragraph_space_key")
print(img_space_id, "Image space ID should be here")
shared_space_id=os.getenv("Shared_space_id")
access_token =  os.getenv("access_token")

#knosys authentication
def get_auth_challenge():
    try:
        url = f"{BASE_URL}/auth/challenge"
        payload = {
            "accessToken": ACCESS_TOKEN,
            "siteId": SITE_ID,
            "userType": USER_TYPE
        }
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=payload, headers=headers, verify=knosys_crt)
        if response.status_code == 200:
            challenge_token = response.json().get("challengeString")
            return challenge_token
        else:
            print("[:x:] Failed to get challenge:", response.text)
            return None
    except Exception as E:
        print(E)
        
def generate_signature(challenge_token):
    try:
        hex_bytes = bytes.fromhex(SECRET_KEY)
        secret_b64 = binascii.b2a_base64(hex_bytes).decode("utf-8").strip()
        secret_key_encoded = binascii.a2b_base64(secret_b64)
        hash_value = HMAC.new(secret_key_encoded, challenge_token.encode("utf-8"), digestmod=SHA256)
        signature = binascii.b2a_base64(hash_value.digest()).decode("utf-8").strip()
        return signature
    except Exception as E:
        print(E)

def get_auth_token(challenge_token, signature):
    try:
        url = f"{BASE_URL}/auth/token"
        payload = {
            "challenge": challenge_token,
            "signature": signature
        }
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=payload, headers=headers, verify=knosys_crt)
        if response.status_code == 200:
            auth_token = response.json().get("token")
            print(auth_token)
            print("[:white_tick:] Authentication successful! Token received.")
            return auth_token
    
        else:
            print("[:x:] Authentication failed:", response.text)
            return None
    except Exception as e:
        print(e)
    
challenge = get_auth_challenge()
if challenge:
    signature = generate_signature(challenge)
    auth_token = get_auth_token(challenge, signature)
    
Document_Id=""
confluence_email =" "

#knosys credentials
source_url=os.getenv("source_url")
headers_1={"Content-Type":"application/json", "Authorization":f"Bearer {auth_token}"}

#get author email from knosys
def getuserEmail(created_by):
    with open("users.json", "r") as f:
        email_map = json.load(f)
    def get_confluence_email(kiq_email):
        return email_map.get(kiq_email, "Not found")
    return get_confluence_email(created_by)

#fetch_documents
response=requests.get(source_url,headers=headers_1,verify=Conf_crt)
if response.status_code == 200:
    try:
        data = response.json()
        fields = data.get("fields", []) 
        Document_Id = data['detail']['id']
        Created_by=data['detail']['createdByPerson']
        confluence_email=getuserEmail(Created_by)
        title = data['detail']['title']
        print("Document Title:", title)
    except ValueError:
        print("Failed to parse JSON.")
else:
    print(f"Request failed with status code: {response.status_code}")

#confluence_credentials   
api_token=os.getenv("CONFLUENCE_API_TOKEN")
confluence_url =os.getenv("CONFLUENCE_URL")
auth = HTTPBasicAuth(confluence_email, api_token)
headers={"Content-Type": "application/json"}

def color_formatter(html_content):
    def rgb_to_hex(match):
        rgba = [float(x.strip()) for x in match.group(1).split(',')]
        r, g, b = map(int, rgba[:3])
        return f'#{r:02x}{g:02x}{b:02x}'

    def convert_units(style):
        style = re.sub(r'([\d.]+)\s*cm', lambda m: f"{float(m.group(1)) * 37.8:.2f}px", style)
        style = re.sub(r'([\d.]+)\s*pt', lambda m: f"{float(m.group(1)) * 1.333:.2f}px", style)
        return style

    def update_style_with_background(style, bg_color):
        styles = dict(item.split(":", 1) for item in style.split(";") if item.strip())
        styles['background-color'] = bg_color
        return "; ".join(f"{k.strip()}:{v.strip()}" for k, v in styles.items()) + ";"

    # Step 1: Convert rgba() or rgb() to hex
    html_content = re.sub(r'rgba?\(([^)]+)\)', rgb_to_hex, html_content)

    soup = BeautifulSoup(html_content, "lxml")

    # Step 2: Replace <h1> to <h6> with <strong>, preserving content and attributes
    for h in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']):
        strong = soup.new_tag("strong")
        # Copy attributes
        for attr, val in h.attrs.items():
            strong[attr] = val
        # Copy children (preserve nested tags)
        strong.extend(h.contents)
        h.replace_with(strong)
    for macro in soup.find_all('ac:structured-macro', attrs={'ac:name': 'include'}):
        br_tag = soup.new_tag("br")
        macro.insert_before(br_tag)
        
    for macro in soup.find_all('ac:structured-macro', attrs={'ac:name': 'rw-ui-tabs-macro'}):
        li_parent = macro.find_parent("li")
        if li_parent:
            # Ensure <br> is not already present just before
            prev_el = macro.find_previous_sibling()
            if not (prev_el and prev_el.name == "br"):
                br_tag = soup.new_tag("br")
                macro.insert_before(br_tag)
    
    for tag in soup.find_all(lambda t: t.has_attr('class') and 'alt3' in t.get('class', [])):
        style = tag.get("style", "")
        # Avoid double-adding color
        if "color:" not in style:
            if style and not style.strip().endswith(";"):
                style += ";"
                
            style += " color: red;"
        tag['style'] = style.strip()
        
    for tag in soup.find_all(lambda t: t.has_attr('class') and 'alt2' in t.get('class', [])):
        style = tag.get("style", "")
        # Avoid double-adding color
        if "color:" not in style:
            if style and not style.strip().endswith(";"):
                style += ";"
            style += " color: green;"
        tag['style'] = style.strip()
        
    # Step 3: Convert units and ensure styles are preserved
    for tag in soup.find_all(True):
        style = tag.get('style', '')
        style = convert_units(style)

        # Check for background color
        match = re.search(r'background-color:\s*(#[0-9a-fA-F]{6})', style)
        if match:
            bg_color = match.group(1)
            updated_style = update_style_with_background(style, bg_color)
            tag['style'] = updated_style

            # Set or remove data-highlight-colour
            if tag.name in ['td', 'th']:
                tag['data-highlight-colour'] = bg_color
            else:
                tag.attrs.pop('data-highlight-colour', None)
        else:
            if style.strip():
                tag['style'] = style
            elif 'style' in tag.attrs:
                del tag['style']

    # Step 4: Clean up table attributes
    for table in soup.find_all('table'):
        table.attrs.pop('width', None)
        style = table.get('style', '')
        style = re.sub(r'width\s*:\s*[^;]+;?', '', style).strip().rstrip(';')
        table['data-layout'] = 'default'
        if style:
            table['style'] = style

    # Optionally write to file
    with open("sample.html", "w", encoding="utf-8") as f:
        f.write(str(soup))

    return str(soup)

def get_page_by_title(space_key,title):
    try:
        url = f"https://api.atlassian.com/ex/confluence/{cloud_id}/wiki/api/v2/pages?title={title}&spaceKey={space_key}"
        response = requests.get(url, headers=headers, auth=auth, params=params,verify=Conf_crt)
        if response.status_code == 200 and response.json()["size"] > 0:
            # print(response.status_code,"-->",response.text)
            print("Page Title fetched!")
            return response.json()["results"][0]
        else:
            print(response.status_code,"-->",response.text)
    except Exception as E:
        print(E)

def get_current_version(page_id):
    url = f"https://api.atlassian.com/ex/confluence/{cloud_id}/wiki/api/v2/pages/{page_id}"
    resp = requests.get(url, headers=headers, auth=auth,verify=Conf_crt)
    if resp.status_code == 200:
        return resp.json()['version']['number']
    else:
        print(f"Failed to get page version: {resp.status_code} - {resp.text}")
        return None
    
def create_page(space_key, title, content,curr_space_id):
    url = f"https://api.atlassian.com/ex/confluence/{cloud_id}/wiki/api/v2/pages"
    print(url,space_key, title, content)
    data = {
  "spaceId": curr_space_id,
  "title": title,
  "body": {
    "value": content,
    "representation": "storage",
  }
    }
    try:
        response = requests.post(url, headers=headers, auth=auth, data=json.dumps(data),verify=Conf_crt)
        if(response.status_code==200):
            response_json = response.json()
            # print(response.status_code,"-->",response.text)
            created_page_Id=response_json.get("id")
            return created_page_Id
        else:
            print("wrong")
            print(response.status_code,"-->",response.text)
    except Exception as e:
        print(e)

def attach_file(page_id, file_path, file_name):
    if file_name == "2e6d82ef-524c-ea11-a960-000d3ad095fb.png":
        print(f"Skipped upload for unwanted image: {file_name}")
        return None
    upload_url = f"https://api.atlassian.com/ex/confluence/{cloud_id}/wiki/rest/api/content/{page_id}/child/attachment"
    
    headers_no_json = {
        "X-Atlassian-Token": "no-check",  # prevents XSRF check
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}"
    }
    with open(file_path, "rb") as f:
        files = {
            'file': (file_name, f, 'image/png')
        }
        response = requests.post(upload_url, headers=headers_no_json, auth=auth, files=files,verify=Conf_crt)
    try:
        if response.status_code == 200 or response.status_code == 201:
            print(f"Uploaded: {file_name}")
            return response.json()
        else:
            print(f"Failed to upload {file_name}: {response.status_code} - {response.text}")
            return None
    except Exception as E:
        print(e)

def update_page(page_id, title, html_content, current_version):
    try:
        url = f"https://api.atlassian.com/ex/confluence/{cloud_id}/wiki/api/v2/pages/{page_id}"
        data = {
            "id": page_id,
            "status": "current",
            "title": title,
            "version": {"number": current_version + 1},
            "body": {
                    "value": html_content,
                    "representation": "storage"
            }
        }
        response = requests.put(url, headers=headers, auth=auth, data=json.dumps(data),verify=Conf_crt)
        print(response.status_code)
        if(response.status_code == 200):
            # print(response.status_code,"-->",response.text)
            print("page updated")
        else:
            print(response.status_code,"-->",response.text)
        return None
    except Exception as E:
        print(E)
        
external_info_list = data.get("external", {}).get("information", [])
info_lookup = {item["informationId"]: item for item in external_info_list if "informationId" in item}

def generate_image_macro_img(filename):
    if filename == "2e6d82ef-524c-ea11-a960-000d3ad095fb.png":
        print(f"Skipped macro generation for: {filename}")
        return " "
#     return f'''
# <ac:image>
#   <ri:attachment ri:filename="{filename}"/>
# </ac:image>
# '''.strip()
    

def generate_image_macro_img_1(filename):
    print("filename123",filename)
    if filename == "2e6d82ef-524c-ea11-a960-000d3ad095fb.png":
        print(f"Skipped macro generation for: {filename}")
        return " "
    print("filename123",filename)
    return f'''<p>
<ac:image>
  <ri:attachment ri:filename="{filename}"/>
</ac:image></p>
'''
# .strip()
# ac:original-height="600" ac:original-width="800" ac:inline="true" ac:alt="example.png"
image_title_map={}
def get_tooltip_panel_content(external_id):
    try:
        entry = info_lookup.get(external_id)
        if not entry:
            return None
        info_type = entry.get("informationType")
        item_id=entry.get("title")
        content = entry.get("content", "")
        if not content and "fields" in entry:
         for field in entry["fields"]:
            if field.get("name") == "Text":
                content = field.get("value", "")


        def fetch_and_save_image(item_id):
            url = f'https://rest.opt.knoiq.co/api/v2/resources/images/{item_id}'
            response = requests.get(url, headers=headers_1,verify=knosys_crt)

            if response.status_code == 200:
                os.makedirs(images_folder, exist_ok=True)
                filepath = os.path.join(images_folder, f"{item_id}.png")
                with open(filepath, "wb") as f:
                    f.write(response.content)
                return filepath
            else:
                return None
        
        if info_type == "Image / screenshot":
            soup = BeautifulSoup(content, "html.parser")
            img_tag = soup.find("img")
            if img_tag and img_tag.get("itemid"):
                item_id = img_tag["itemid"]
                if item_id:
                    image_title_map[item_id] = entry.get("title", item_id)
                    filepath = fetch_and_save_image(item_id)
                    if filepath:
                        print("get_tooltip_panel_content")
                        return generate_image_macro_img_1(os.path.basename(filepath))
            return None

        if info_type not in ["Null","SharedParagraph"] :
            soup = BeautifulSoup(content, "html.parser")
            img_tags = soup.find_all("img")
            for img_tag in img_tags:
                item_id = img_tag.get("itemid")
                if item_id:
                    image_title_map[item_id] = entry.get("title", item_id)
                    filepath = fetch_and_save_image(item_id)
                    if filepath:
                        return generate_image_macro_img_1(os.path.basename(filepath))

            title = entry.get("title", "Untitled")
            # print("title12340",title)
            # page_id=get_page_by_title(space_key,title)
            # if not page_id:
            #     content_with_macros = download_images_from_html_and_update_content(content)
            #     cleaned_content = color_formatter(content_with_macros)
            #     create_page(tooltip_space_key, title, cleaned_content)
            # return f"{title}\n{content}"
            return content

        return None
    except Exception as E:
        print(E)

def highlight_externalid(html_content):
    try:
        pattern = re.compile(
            r'(<[^>]*data-externalid="(?P<id>[^"]+)"[^>]*>)(?P<text>.*?)</[^>]+>', 
            re.DOTALL | re.IGNORECASE
        )
        
        def html_to_tooltip_text(html_fragment):
            soup = BeautifulSoup(html_fragment, "html.parser")
            for tag in soup.find_all(["script", "style"]):
                tag.decompose()
            return str(soup).strip()
        def repl(match):
            full_tag, external_id, inner_text = match.group(1), match.group(2), match.group(3)
            result = get_tooltip_panel_content(external_id)
            print("result12",result)
            if not result:
                return match.group(0)
            if not inner_text and result.strip().startswith("<ac:image"):
                return result
            if inner_text and result.strip().startswith("<ac:image"):
                return f"{inner_text}{result}"
            tooltip_text = html_to_tooltip_text(result)
            cleaned_text = tooltip_text.replace("<em>", "").replace("</em>", "").replace("'", "")
#             return f'''
# <ac:structured-macro ac:name="tooltip" ac:schema-version="1">
#   <ac:parameter ac:name="linkText">{inner_text.strip()}</ac:parameter>
#   <ac:rich-text-body>
#     {cleaned_text}
#   </ac:rich-text-body>
# </ac:structured-macro>
# '''.strip()

            def generate_id(length=8):
                return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

            outer_local_id = generate_id()
            outer_macro_id = generate_id()
            inner_local_id = generate_id()
            inner_macro_id = generate_id()
            
            print("inner_text_123",inner_text,"hello",cleaned_text)
            print( image_title_map)
            
            def extract_image_title_from_macro(cleaned_text, image_title_map):
                soup = BeautifulSoup(cleaned_text, "html.parser")
                ri_tag = soup.find("ri:attachment")
                if ri_tag and ri_tag.get("ri:filename"):
                    filename = ri_tag["ri:filename"]
                    item_id = filename.replace(".png", "")
                    return image_title_map.get(item_id, item_id)
                return None
            cleaned_text=sync_hidden_links_with_shared_pages_using_data(cleaned_text,data)
            if "<ac:image" in cleaned_text:
                inner_text = extract_image_title_from_macro(cleaned_text, image_title_map)
                
                print(inner_text,"inner_text")
            print(inner_text,"hihello",cleaned_text)
            return f'''<ac:structured-macro ac:name="rw-ui-tabs-macro" ac:schema-version="1" data-layout="default" ac:local-id="{outer_local_id}" ac:macro-id="{outer_macro_id}">
            <ac:rich-text-body>
            <ac:structured-macro ac:name="rw-tab" ac:schema-version="1" data-layout="default" ac:local-id="{inner_local_id}" ac:macro-id="{inner_macro_id}">
            <ac:parameter ac:name="title">{inner_text.strip()}</ac:parameter>
            </ac:structured-macro>
             {cleaned_text}
            </ac:rich-text-body>
            </ac:structured-macro>'''.strip()
        #     safe_title = title.strip().strip('"')
        #     print(safe_title,tooltip_space_key,"Test1245")
        #     return f'''
        # <ac:structured-macro ac:name="rw-ui-tabs-macro" ac:schema-version="1" data-layout="default" ac:local-id="{outer_local_id}" ac:macro-id="{outer_macro_id}">
        #     <ac:rich-text-body>
        #     <ac:structured-macro ac:name="rw-tab" ac:schema-version="1" data-layout="default" ac:local-id="{inner_local_id}" ac:macro-id="{inner_macro_id}">
        #     <ac:parameter ac:name="title">{inner_text.strip()}</ac:parameter>
        #     </ac:structured-macro>
        #     <ac:structured-macro ac:name="include" ac:schema-version="1" data-layout="default">
        #     <ac:parameter ac:name="">
        #     <ac:link>
        #     <ri:page ri:space-key="{tooltip_space_key}" ri:content-title="{safe_title}"/>
        #     </ac:link>
        #     </ac:parameter>
        #     </ac:structured-macro>
        #     </ac:rich-text-body>
        #     </ac:structured-macro>'''.strip()
        return pattern.sub(repl, html_content)

    except Exception as e:
        print("Error in highlight_externalid:", e)
        return html_content

def download_images_from_html_and_update_content(html_content):
    try:    
        soup = BeautifulSoup(html_content, "html.parser")
        img_tags = list(soup.find_all("img"))
        for img_tag in img_tags:
            item_id = img_tag.get("itemid")
            if not item_id:
                continue
            url = f'https://rest.opt.knoiq.co/api/v2/resources/images/{item_id}'
            response = requests.get(url, headers=headers_1,verify=knosys_crt)
            if response.status_code == 200:
                os.makedirs(images_folder, exist_ok=True)
                filename = f"{item_id}.png"
                filepath = os.path.join(images_folder, filename)
                with open(filepath, "wb") as f:
                    f.write(response.content)
                image_macro = generate_image_macro_img_1(filename)
                img_tag.replace_with(BeautifulSoup(image_macro, "html.parser"))
            else:
                print(f"Failed to download image {item_id}. Status code: {response.status_code}")
        return str(soup)
    except Exception as E:
        print(E)


def extract_shared_content(data):
    shared_content = []

    def recurse_children(children):
        for child in children:
            try:
                detail = child.get("detail", {})
                if detail.get("itemType") == "SharedParagraph":
                    fields = child.get("fields", [])
                    title_value = ""
                    value = ""

                    for field in fields:
                        if field.get("name") == "ParagraphTitle":
                            title_value = field.get("value").strip()
                            print("title_value_test",title_value)
                        if field.get("name") == "Text":
                            value = field.get("value")
                            print(value,title_value,"frtyf")

                    if title_value and value:
                        # Highlight external IDs (to process image macros)
                        if 'data-externalid="' in value:
                            value = highlight_externalid(value)

                        # Process images in the shared paragraph text
                        value = download_images_from_html_and_update_content(value)
                        print("value for image macro",value)
                        # Check if an image exists in the value
                        if "<ac:image>" in value:
                            # If an image exists, create a separate page for the image
                            # Extract item_id from the image macro (we assume the item_id is part of the filename)
                            image_item_id = extract_item_id_from_image_macro(value)
                            print("image_item_id",image_item_id)
                            if image_item_id:
                                image_page_title = f"{image_item_id}"
                                existing_image_page = get_page_by_title(image_hub_space_key,image_page_title)
                                if not existing_image_page:
                                    image_page_content = f'<ac:image><ri:attachment ri:filename="{image_item_id}.png"/></ac:image>'
                                    # Create the page for the image
                                    image_page_id = create_page(image_hub_space_key, image_page_title, image_page_content,img_space_id)
                                    for file in os.listdir(images_folder):
                                        file_path_full = os.path.join(images_folder, file)
                                        attach_file(image_page_id, file_path_full, file)
                                    # Update the page with the current content
                                    current_version = get_current_version(image_page_id)
                                    if current_version is not None:
                                        update_page(image_page_id, image_page_title,image_page_content, current_version)
                                    else:
                                        print(f"Could not fetch version for {title_value}")
                                else:
                                    print(f"[i] Image page already exists: {image_page_title}")
                                
                                # Add the Include Page macro to include the image page
                                include_page_macro = f'''
<ac:structured-macro ac:name="include" ac:schema-version="1">
  <ac:parameter ac:name="">
    <ac:link>
      <ri:page ri:space-key="{image_hub_space_key}" ri:content-title="{image_page_title}" />
    </ac:link>
  </ac:parameter>
</ac:structured-macro>
'''
                                # value += f"\n{include_page_macro}"
                            pattern = rf'<ac:image>.*?<ri:attachment ri:filename="{re.escape(image_item_id)}\.png".*?</ac:image>'
                            value = re.sub(pattern, include_page_macro, value, flags=re.DOTALL)
                        # Create the shared paragraph page if it does not already exist
                        clean_title=title_value.strip().strip('"')
                        existing_page = get_page_by_title(shared_paragraph_space_key,clean_title)
                        if not existing_page:
                            shared_content.append({
                                "title": title_value,
                                "content": value
                            })

                            try:
                                clean_html=color_formatter(value)
                                page_id = create_page(shared_paragraph_space_key, title_value, clean_html,shared_space_id)
                                uploaded = []
                            except Exception as e:
                                print(f"Failed to create page '{title_value}': {e}")

                if "children" in child:
                    recurse_children(child["children"])
            except Exception as e:
                print(f"Error processing child: {e}")

    try:
        recurse_children(data.get("children", []))
        return shared_content
    except Exception as e:
        print(e)

def extract_item_id_from_image_macro(html_content):
    pattern = r'<ac:image>.*?<ri:attachment ri:filename="([^"]+)\.png".*?</ac:image>'
    match = re.search(pattern, html_content, re.DOTALL)
    if match:
        return match.group(1)
    return None

extract_macro = extract_shared_content(data)
html_parts = []

def includePagemacro(data):
    try:
        include_blocks = ""
        def recurse_children(children):
            nonlocal include_blocks
            for child in children:
                try:
                    detail = child.get("detail", {})
                    if detail.get("itemType") == "SharedParagraph":
                        fields = child.get("fields", [])
                        title_value = ""
                        for field in fields:
                            if field.get("name") == "ParagraphTitle":
                                title_value = field.get("value")
                        if not title_value:
                            title_value = detail.get("title")
                        if title_value:
                            clean_title=title_value.strip().strip('"')
                            existing_page=get_page_by_title(shared_paragraph_space_key,clean_title)
                            if existing_page:
                                include_block = f'''
<ac:structured-macro ac:name="include" ac:schema-version="1">
  <ac:parameter ac:name="">
    <ac:link>
      <ri:page ri:space-key="{shared_paragraph_space_key}" ri:content-title="{clean_title}" />
    </ac:link>
  </ac:parameter>
</ac:structured-macro>
'''
                                include_blocks += include_block
                            else:
                                print(f"Page '{title_value}' not found in Confluence.")
                    if "children" in child:
                        recurse_children(child["children"])
                except Exception as e:
                    print(f"Error processing child: {e}")
        if isinstance(data, dict) and "children" in data:
            recurse_children(data["children"])
        elif isinstance(data, list):
            recurse_children(data)

        return include_blocks
    except Exception as e:
        print("[:x:] Unexpected error during include macro generation:", str(e))
        return None
def collect_all_items(data):
    collected = []

    def recurse(children):
        for item in children:
            if "detail" in item:
                collected.append(item)
            if "children" in item:
                recurse(item["children"])

    top_level = data.get("children", [])
    recurse(top_level)
    return collected


def sync_hidden_links_with_shared_pages_using_data(hidden_text, data):
    print("sync")
    try:
        soup = BeautifulSoup(hidden_text or "", "html.parser")
        updated = False

        # Step 1: Get all 'detail' items from nested structure
        items = collect_all_items(data)
   
        if not isinstance(items, list):
            print(" Expected list of items, got:", type(items))
            return hidden_text

        # Step 2: Loop through all <a> tags with data-itemid
        for a_tag in soup.find_all("a", attrs={"data-itemid": True}):
            itemid = a_tag["data-itemid"]
            print("itemid",itemid)
            anchor_text = a_tag.get_text(strip=True)
            print("🔍 anchor_text:", anchor_text)
            
            # Step 3: Find matching item by ID
            match = None
            for item in items:
                detail = item.get("detail", {})
                if detail.get("id") == itemid:
                    match = item
                    break

            if not match:
                print(f"[!] No match found for itemid: {itemid}")
                continue
            if detail.get("itemType") == "Document":

                # Step 4: Get the title
                title = match.get("detail", {}).get("title")
                if not title:
                    title = next((f.get("value") for f in match.get("fields", []) if f.get("name") == "DocumentTitle"), None)

                if not title:
                    print(f"[!] No title for itemid: {itemid}")
                    continue

                print("🔗 anchor title:", title)

                # Step 5: Get the Confluence page
                clean_title=title.strip().strip('"')
                main_page = get_page_by_title(space_key, clean_title)
                print("main_page",main_page)
                if not main_page:
                    print(title,"hello no page")
                    create_page(space_key, title,"To be migrated!",space_id)
                    
                # Step 6: Replace the <a> with Confluence link macro
                link_macro = f'''
    <ac:link>
    <ri:page ri:content-title="{clean_title}" ri:space-key="{space_key}" />
    <ac:plain-text-link-body><![CDATA[{anchor_text}]]></ac:plain-text-link-body>
    </ac:link>
    '''
                a_tag.replace_with(BeautifulSoup(link_macro, "html.parser"))
                updated = True
            elif detail.get("itemType") == "Link":
                # 🔍 Extract the external URL from fields
                # url = next((f.get("value") for f in match.get("fields", []) if f.get("name") == "URL"), None)
                fields = match.get("fields", [])
                url = next((f.get("value") for f in fields if f.get("name") == "URL"), None)
                link_title = next((f.get("value") for f in fields if f.get("name") == "LinkTitle"), anchor_text)

                if not url:
                    print(f"[!] No URL found for itemid: {itemid}")
                    continue

                print(f"🔗 External link found for itemid {itemid}: {url}")
                link_macro=f'<a href="{url}">{anchor_text}</a>'
#                 link_macro = f'''
# <ac:link>
#   <ri:url ri:value="{url}" />
#   <ac:plain-text-link-body><![CDATA[{anchor_text}]]></ac:plain-text-link-body>
# </ac:link>
# '''.strip()
                print(link_macro,"4568")

                a_tag.replace_with(BeautifulSoup(link_macro, "html.parser"))
                updated = True
                

        return str(soup) if updated else hidden_text

    except Exception as e:
        print(f"Error in sync_hidden_links_with_shared_pages_using_data: {e}")
        return hidden_text
    
def fix_broken_links(html):
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href="#"):
        if a.text.strip().startswith("yesopt.us"):
            a['href'] = "https://" + a.text.strip()
            a['target'] = "_blank"
            a['class'] = 'externallink'
    return str(soup)


def extract_content_from_fields(child):
    try:
        fields = child.get("fields", [])
        item_type = child.get("detail", {}).get("itemType")
        
        

        if item_type == "SharedParagraph":
            include_macro = includePagemacro({"children": [child]})
            if include_macro:
                html_parts.append(include_macro)
            return
        if item_type == "HtmlAsset":
            for field in fields:
                if field.get("name") == "HTMLText":
                    html_text = field.get("value", "")
                    if html_text:
                        soup = BeautifulSoup(html_text, "html.parser")
                        body_content = soup.body or soup
                        html_parts.append(str(body_content))
                        return              
        link_text = None
        hidden_text = None
        bookmark = None
        for field in fields:
            name = field.get("name")
            value = field.get("value", "")
            if field.get("name") == "Bookmark":
                 bookmark = field.get("value")  
                 if bookmark and bookmark != "Introduction" :
                    anchor_macro = f"""
        <ac:structured-macro ac:name="anchor">
        <ac:parameter ac:name="">{bookmark}</ac:parameter>
        </ac:structured-macro>
        """
                    print(anchor_macro)
                    html_parts.append(anchor_macro)
            if name == "LinkText":
                link_text = value
                print(link_text,"testing")
            elif name == "HiddenText":
                value = fix_broken_links(value)
                hidden_text = value
                print(link_text,hidden_text,"testing")
            # elif name == "HTMLText":
            #     html_parts.append(value)
            # elif name in ["Text", "VisibleText"] and value:
            #     html_parts.append(value)
            elif name in ["Text", "VisibleText"] and value:
                if 'data-itemid="' in value:
                    print("📌 Found anchor with data-itemid inside Text, calling sync...")
                    value = sync_hidden_links_with_shared_pages_using_data(value, data)
                html_parts.append(value)

        # Step 1: Ensure we have both link_text and hidden_text
        if not link_text or not hidden_text:
            return

        # Step 2: Clean and enhance hidden_text
        hidden_text = highlight_externalid(hidden_text)
        print("sync")
        hidden_text = sync_hidden_links_with_shared_pages_using_data(hidden_text, data)
        hidden_text = download_images_from_html_and_update_content(hidden_text)

        # Step 3: Replace image macros
        image_macros = re.findall(r"<ac:image>.*?</ac:image>", hidden_text, flags=re.DOTALL)
        for macro in image_macros:
            item_id = extract_item_id_from_image_macro(macro)
            if not item_id:
                continue

            image_filename = f"{item_id}.png"
            image_page_title = f"{item_id}"
            image_path = os.path.join(images_folder, image_filename)

            existing_image_page = get_page_by_title(image_hub_space_key, image_page_title)
            if not existing_image_page:
                image_page_content = f"<ac:image><ri:attachment ri:filename='{image_filename}'/></ac:image>"
                image_page_id = create_page(image_hub_space_key, image_page_title, image_page_content,img_space_id)

                if os.path.exists(image_path):
                    attach_file(image_page_id, image_path, image_filename)

                current_version = get_current_version(image_page_id)
                if current_version:
                    update_page(image_page_id, image_page_title, image_page_content, current_version)

            # Replace image macro with include macro
            include_macro = f"""
<ac:structured-macro ac:name="include" ac:schema-version="1">
  <ac:parameter ac:name="">
    <ac:link>
      <ri:page ri:space-key="{image_hub_space_key}" ri:content-title="{image_page_title}" />
    </ac:link>
  </ac:parameter>
</ac:structured-macro>
"""
            hidden_text = hidden_text.replace(macro, include_macro)

        # Step 4: Create the shared page if not exists
        clean_title = link_text.strip().strip('"')
        existing_hidden_page = get_page_by_title(shared_paragraph_space_key,clean_title)
        
        if not existing_hidden_page:
            with open("test_output_1.html", "w", encoding="utf-8") as f:
                f.write(hidden_text)
                clean_html=color_formatter(hidden_text)
            create_page(shared_paragraph_space_key, clean_title,clean_html,shared_space_id)

        # Step 5: Wrap it with expand macro
        print("link_text_demo",link_text)
        expand_with_include = f"""
<ac:structured-macro ac:name="expand">
  <ac:parameter ac:name="title">{link_text}</ac:parameter>
  <ac:rich-text-body>
    <ac:structured-macro ac:name="include" ac:schema-version="1">
      <ac:parameter ac:name="">
        <ac:link>
          <ri:page ri:space-key="{shared_paragraph_space_key}" ri:content-title="{clean_title}" />
        </ac:link>
      </ac:parameter>
    </ac:structured-macro>
  </ac:rich-text-body>
</ac:structured-macro>
"""
        html_parts.append(expand_with_include)

    except Exception as e:
        print(f"Error in extract_content_from_fields: {e}")


def replace_image_macros_with_include_pages(html_content):
    try:
        print("replace_image_macros_with_include_pages")

        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')

        matches = []
        for img_tag in soup.find_all('ac:image'):
            attach = img_tag.find('ri:attachment')
            if attach and attach.get('ri:filename'):
                filename = attach['ri:filename']
                if filename.lower().endswith('.png'):
                    matches.append((filename, img_tag))

        print("Image matches found:", [m[0] for m in matches])

        for filename, img_tag in matches:
            item_id = filename.replace(".png", "")
            image_page_title = f"{item_id}"
            image_page_content = f"<ac:image><ri:attachment ri:filename='{filename}'/></ac:image>"

            # Create page
            image_page_id = create_page(image_hub_space_key, image_page_title, image_page_content,img_space_id)

            # Attach image
            file_path_full = os.path.join(images_folder, filename)
            if os.path.exists(file_path_full):
                attach_file(image_page_id, file_path_full, filename)
                current_version = get_current_version(image_page_id)
                if current_version:
                    update_page(image_page_id, image_page_title, image_page_content, current_version)

            # Create include macro and replace
            include_macro = f'''
<ac:structured-macro ac:name="include" ac:schema-version="1">
  <ac:parameter ac:name="">
    <ac:link>
      <ri:page ri:space-key="{image_hub_space_key}" ri:content-title="{image_page_title}" />
    </ac:link>
  </ac:parameter>
</ac:structured-macro>
'''.strip()

            img_tag.replace_with(BeautifulSoup(include_macro, "html.parser"))

        return str(soup)
    except Exception as e:
        print(f"Error replacing image macros: {e}")
        return html_content

def recurse_children(children):
    try:
        for child in children:
            if "fields" in child:
                extract_content_from_fields(child)
                html_content = "\n".join(html_parts)
            if "children" in child and child["children"]:
                recurse_children(child["children"])
    except Exception as E:
        print(E)
        
if "fields" in data:
    extract_content_from_fields(data)
if "children" in data:
    recurse_children(data["children"])
html_content = "\n".join(html_parts)

def find_fragment_in_soup(soup, html_fragment):
    try:
        fragment_soup = BeautifulSoup(html_fragment, 'html.parser')
        fragment_elements = list(fragment_soup.contents)
        if not fragment_elements:
            return None

        for fragment_el in fragment_elements:
            candidates = soup.find_all(fragment_el.name)
            for candidate in candidates:
                if str(candidate) == str(fragment_el):
                    return candidate

        return None
    except Exception as E:
        print(E)

def generate_confluence_storage_format(html_content, data):
    try:
        # Your anchor macro as a string
        page_top_anchor = '''<ac:structured-macro ac:name="anchor"><ac:parameter ac:name="">PageTop</ac:parameter></ac:structured-macro>\n'''

        # Simply prepend it before the HTML
        final_html = page_top_anchor + html_content

        return final_html

    except Exception as e:
        print(f"Error in generate_confluence_storage_format: {e}")
        return None


# def generate_confluence_storage_format(html_content, data):
#     try:
#         soup = BeautifulSoup(html_content, 'html.parser')

#         # Check if anchor macro already exists
#         existing_anchor = soup.find('ac:structured-macro', {'ac:name': 'anchor'})
#         if not existing_anchor:
#             anchor_macro = soup.new_tag('ac:structured-macro', **{'ac:name': 'anchor'})
#             param = soup.new_tag('ac:parameter', **{'ac:name': ''})
#             param.string = 'PageTop'
#             anchor_macro.append(param)

#             # Insert the anchor macro as the first element in the document
#             if soup.contents:
#                 soup.insert(0, anchor_macro)
#             else:
#                 # If the document is empty, just append the anchor
#                 soup.append(anchor_macro)

#         return str(soup)

# def generate_confluence_storage_format(html_content, data):
#     try:
#         soup = BeautifulSoup(html_content, 'html.parser')
#         links = soup.find_all('a', href=re.compile(r'^#\w+$'))
#         bookmarks_in_html = {link['href'][1:] for link in links}  # Set of bookmark names
#         processed_bookmarks = set()
#         back_to_top_link = soup.find('a', href='#PageTop')
#         if back_to_top_link:
#             if not soup.find('ac:structured-macro', {'ac:name': 'anchor'}):
#                 anchor_macro = soup.new_tag('ac:structured-macro', **{'ac:name': 'anchor'})
#                 param = soup.new_tag('ac:parameter', **{'ac:name': ''})
#                 param.string = 'PageTop'
#                 anchor_macro.append(param)
#                 if soup.body:
#                     soup.body.insert(0, anchor_macro)
#                 else:
#                     soup.insert(0, anchor_macro)
#         for item in data.get('children', []):
#             bookmark = next(
#                 (f['value'] for f in item.get('fields', []) if f.get('name') == 'Bookmark' and f.get('value')),
#                 None
#             )
#             if not bookmark:
#                 continue
#             if bookmark not in bookmarks_in_html:
#                 continue
#             if bookmark in processed_bookmarks:
#                 continue
#             processed_bookmarks.add(bookmark)
#             anchor_macro = soup.new_tag('ac:structured-macro', **{'ac:name': 'anchor'})
#             param = soup.new_tag('ac:parameter', **{'ac:name': ''})
#             param.string = bookmark
#             anchor_macro.append(param)
#             inserted = False
#             for child in item.get('children', []):
#                 for f in child.get('fields', []):
#                     text_value = f.get('value')
#                     if not text_value:
#                         continue
#                     matched_element = find_fragment_in_soup(soup, text_value)
#                     print(matched_element)
#                     if matched_element:
#                             matched_element.insert(0, anchor_macro)  
#                     else:
#                             matched_element.insert_before(anchor_macro)
#                     inserted = True
#                     break
#                 if inserted:
#                     break
#             if not inserted:
#                 if soup.body:
#                     soup.body.append(anchor_macro)
#                 else:
#                     soup.append(anchor_macro)
#         return str(soup)
#     except Exception as e:
#         print(f"Error in generate_confluence_storage_format: {e}")
#         return None

html_content = "\n".join(html_parts)
# html_content= generate_confluence_storage_format(html_content, data)
html_content = highlight_externalid(html_content)
html_content = download_images_from_html_and_update_content(html_content)
print("html_content_before_replace",html_content)
html_content = replace_image_macros_with_include_pages(html_content)
html_content= generate_confluence_storage_format(html_content, data)

soup = BeautifulSoup(html_content, 'html.parser')
external_links = soup.find_all('a', class_='externallink')
data_itemid = set()
for link in external_links:
    itemid = link.get('data-itemid')
    if itemid:
        data_itemid.add(itemid)
itemid_to_conf={}
for itemid in data_itemid:
    pagefetch_url=f"https://rest.opt.knoiq.co/api/v2/admin/documents/{itemid}"
    response=requests.get(pagefetch_url,headers=headers_1,verify=knosys_crt)
    if response.status_code == 200:
        try:
            data = response.json()
            fields = data.get("fields", []) 
            title_1 = next((f.get("value", "Untitled Page") for f in response.json().get("fields", []) if f.get("name") == "DocumentTitle"), "Untitled Page")
            clean_title=title_1.strip().strip('"')
            results = get_page_by_title(space_key,clean_title)
            if results:
                itemid_to_conf[itemid] = title_1
        except ValueError:
            print("Failed to parse JSON.")
    else:
        print("page not exists",itemid)
for link in external_links:
    itemid = link.get('data-itemid')
    anchor_text = link.text.strip().strip('"')
    if itemid in itemid_to_conf:
        conf_title = itemid_to_conf[itemid]

        ac_link = soup.new_tag("ac:link")
        ri_page = soup.new_tag("ri:page")
        ri_page['ri:content-title'] = conf_title
        link_body = soup.new_tag("ac:link-body")
        span = soup.new_tag("span")
        span.string = anchor_text
        link_body.append(span)
        ac_link.append(ri_page)
        ac_link.append(link_body)  
        link.replace_with(ac_link)
html_content = str(soup)   
# Replace problematic tags with safe <span> equivalents

html_content = html_content.replace("<b","<strong").replace("</b>", "</strong>")
# html_content = html_content.replace("<i>", '<span style="font-style: italic;">').replace("</i>", "</span>")
html_content = html_content.replace("<em>", '<span style="font-style: italic;">').replace("</em>", "</span>")
# html_content = re.sub(r'</?(strong|b|i|em|span)( [^>]*)?>', '', html_content)
html_content = re.sub(r'<(/?){[^}]+}(\w+)', r'<\1\2', html_content)
html_content = re.sub(r"<(\w+)[^>]*>\s*</\1>", "", html_content)

with open("test_output_2.html", "w", encoding="utf-8") as f:
    f.write(html_content)

try:
    clean_html=color_formatter(html_content)
    with open("test_output.html", "w", encoding="utf-8") as f:
        f.write(clean_html)
    clean_title = title.strip().strip('"')
    page = get_page_by_title(space_key,clean_title)
    print(page,"demo12",title,space_key)
    print(page, "demo12", repr(title), space_key)
    if not page:
        page_id = create_page(space_key, title, clean_html,space_id)
        if page_id:
            print(f"✅ Page created: {title}")
            keywords = data.get('meta', {}).get('keywords', '')
            print("Keywords:", keywords)
            # if keywords != "null":
            if isinstance(keywords, str) and keywords.lower() != "null" and keywords.strip():
                labels=[k.strip().replace(" ", "-") for k in keywords.split(",")]
                print(labels)
                def chunk_labels(label_list, size=15):
                    for i in range(0, len(label_list), size):
                        yield label_list[i:i + size]
                def append_labels(page_id, labels):
                    for batch in chunk_labels(labels):
                        print("batch",batch)
                        payload_1 = [{"prefix": "global", "name": label} for label in batch]
                        url = f"https://api.atlassian.com/ex/confluence/{cloud_id}/wiki/rest/api/content/{page_id}/label"
                        response = requests.post(url, headers=headers, auth=auth, json=payload_1,verify=Conf_crt)
                        if response.status_code == 200:
                            print(f"Added batch: {batch}")
                        else:
                            print(f"Failed batch: {batch}")
                            print(response.status_code, response.text)
                append_labels(page_id, labels)
    else:
        page_id=page['id']
        print(page,page_id,"test4t")
        current_version = get_current_version(page_id)
        if current_version is not None:
            update_page(page_id, title, clean_html, current_version)
            print(f"🔄 Page updated: {title}")
            keywords = data.get('meta', {}).get('keywords', '')
            print("Keywords:", keywords)
            # if keywords != "null":
            if isinstance(keywords, str) and keywords.lower() != "null" and keywords.strip():
                labels=[k.strip().replace(" ", "-") for k in keywords.split(",")]
                print(labels)
                def chunk_labels(label_list, size=15):
                    for i in range(0, len(label_list), size):
                        yield label_list[i:i + size]
                def append_labels(page_id, labels):
                    for batch in chunk_labels(labels):
                        print("batch",batch)
                        payload_1 = [{"prefix": "global", "name": label} for label in batch]
                        url = f"https://api.atlassian.com/ex/confluence/{cloud_id}/wiki/rest/api/content/{page_id}/label"
                        response = requests.post(url, headers=headers, auth=auth, json=payload_1,verify=Conf_crt)
                        if response.status_code == 200:
                            print(f"Added batch: {batch}")
                        else:
                            print(f"Failed batch: {batch}")
                            print(response.status_code, response.text)
                append_labels(page_id, labels)
        else:
            print(f"⚠️ Could not get version for {title}")

        uploaded = []

        # STEP 2: Upload images
        for file in os.listdir(images_folder):
            file_path_full = os.path.join(images_folder, file)
            try:
                print(file, "filepathname")
                if file != "2e6d82ef-524c-ea11-a960-000d3ad095fb.png":
                    attach_file(page_id, file_path_full, file)
                    uploaded.append(file)
            except Exception as e:
                print(f"Failed to upload {file}: {e}")

        current_version = get_current_version(page_id)
        if current_version:
            update_page(page_id, title, clean_html, current_version)

        # STEP 3: Update tracking page
        try:
            track_title = "Document - Page Navigation"
            tracking_results = get_page_by_title(space_key,track_title)
            if tracking_results:
                tracking_page = tracking_results
                page_id_track = tracking_page['id']
                current_version = tracking_page['version']['number']

                url = f"https://api.atlassian.com/ex/confluence/{cloud_id}/wiki/api/v2/pages/{page_id_track}?body-format=storage"
                response = requests.get(url, headers=headers, auth=auth,verify=Conf_crt)
                current_body = response.json()["body"]["storage"]["value"]

                new_row = f'''
<tr>
<td>{Document_Id}</td>
<td>{title}</td>
<td><a href="{conf_doc_page}/spaces/{space_key}/pages/{page_id}">{page_id}</a></td>
</tr>
'''

                if "</tbody>" in current_body:
                    updated_body = current_body.replace("</tbody>", new_row + "</tbody>")
                    update_page(
                        page_id_track,
                        tracking_page['title'],
                        updated_body,
                        current_version
                    )
                    print("Tracking page updated with new document entry.")
                else:
                    print("</tbody> not found — is the table structured correctly?")
        except Exception as e:
            print(f"Failed to update tracking page: {e}")

except Exception as e:
    print(f"Failed to create page '{title}': {e}")

# Delete image files
for file in os.listdir(images_folder):
    try:
        os.remove(os.path.join(images_folder, file))
    except Exception as e:
        print(f"Failed to delete {file}: {e}")
