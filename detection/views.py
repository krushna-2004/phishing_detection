from django.shortcuts import render
import re
import os
from django.http import HttpResponseRedirect
from .utils import detect_fraudulent_email
from django.contrib.auth import get_user_model, authenticate, login
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect
from django.http import JsonResponse
import json
from django.contrib.auth import logout
from django.contrib import messages

User = get_user_model()

def welcome(request):
    return render(request, 'detection/home.html', {"user": request.user})

def Info(request):
    if not request.user.is_authenticated:
        messages.warning(request, "⚠️ You must be logged in")
        return redirect('welcome')  # Redirect to the homepage (or any page you want)
    return render(request, 'detection/LearnMore.html')

def Email(request):
    return render(request, 'detection/email_form.html')

def scan_qr(request):
    if not request.user.is_authenticated:
        messages.warning(request, "⚠️ You must be logged in to scan QR")
        return redirect('welcome')  # Redirect to the homepage (or any page you want)
    return render(request, 'detection/qr_scanner.html')

def contact(request):
    if not request.user.is_authenticated:
        messages.warning(request, "⚠️ You must be logged in")
        return redirect('welcome')  # Redirect to the homepage (or any page you want)
    return render(request, 'detection/contact.html')

def about(request):
    if not request.user.is_authenticated:
        messages.warning(request, "⚠️ You must be logged in")
        return redirect('welcome')  # Redirect to the homepage (or any page you want)
    return render(request, 'detection/about.html')

def support(request):
    if not request.user.is_authenticated:
        messages.warning(request, "⚠️ You must be logged in")
        return redirect('welcome')  # Redirect to the homepage (or any page you want)
    return render(request, 'detection/support.html')

phishing_patterns = [
    r"\bexample\.com\b",               # Check for known phishing domains (e.g., example.com)
    r"\b[^\s]+\.ru\b",                 # Check for suspicious top-level domains (e.g., .ru, .xyz, etc.)
    r"@.*\.ru",                        # Check for email-like URLs with suspicious domains (e.g., @example.ru)
    r"[^a-zA-Z0-9:/\-\.]",             # Look for unusual characters that are uncommon in legitimate URLs
    r"^https?://.*\.zip",               # Look for URLs pointing to .zip files (often used in phishing)
    r"\b[\w-]+\.tk\b",                 # Look for .tk domain (commonly used in phishing)
    r"\b[\w-]+\.cf\b",                 # Look for .cf domain (commonly used in phishing)
    r"\b[\w-]+\.ga\b",                 # Look for .ga domain (commonly used in phishing)
    r"//.*\.cn",                       # Look for Chinese domains (.cn) often used in phishing sites
    r"^https?://.*\.bet",               # Look for gambling-related domains (.bet), sometimes used in phishing
    r"\b[\w-]+\.club\b",               # Check for .club domain, often associated with fake websites
    r"login\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}",  # Subdomains with 'login' in them (often part of phishing scams)
    r"secure\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}",  # Subdomains with 'secure' in them (can be a phishing tactic)
    r"^http(s)?://.*\.[a-zA-Z]{2,}",   # Any URL ending with a suspicious domain extension (e.g., .xyz, .co, etc.)
    r"\bhttp[s]?://[a-zA-Z0-9\-]+\.(xyz|top|win|work|space)\b",  # Non-standard TLDs often associated with phishing
    r"@[\w.-]+\.[a-zA-Z]{2,}",         # Check for email address format in URLs, often used in phishing
    r"\bhttps?://[a-zA-Z0-9.-]+/.*\.(exe|bat|scr|js)\b",  # URLs ending with executable file extensions
    r"//.*\.ru\.",                      # Suspicious Russian domains
    r"login[.|\-]secure.*\.com",        # Common phishing technique where legitimate-looking login URLs are created
    r"^http(s)?://.*\.(co|ga|top|cf|tk)\b",  # Check for free TLDs commonly used by phishers
    r"@.*\.org",                        # Look for email-like URL patterns ending in .org (often fake organizations)
    r"^http[s]?://[^/]+\.pro",          # Check for .pro domain (sometimes misused in phishing)
    r"^https?://.*(login|secure|myaccount|update)\.([a-zA-Z0-9\-]+)\b",  # Look for subdomains like 'login', 'secure', etc.
    r"\b[a-zA-Z0-9-]+\.online\b",       # Check for .online domain (often used in phishing)
    r"[^a-zA-Z0-9\/:.-]",               # Check for non-alphanumeric characters outside the URL pattern
    r"[^a-zA-Z0-9\s]+",                 # Suspicious special characters in the URL
    r"^https?://.*\/?checkout.*\.com",  # Check for phishing attempts with fake checkout URLs
    r"^https?://.*\/?login.*\.com",     # Check for fake login URLs
    r"^https?://.*\/?update.*\.com",    # Check for fake update URLs
]
safe_domains = [
    "google.com",        # Search engine and services
    "facebook.com",      # Social media platform
    "twitter.com",       # Social media platform
    "instagram.com",     # Social media platform
    "linkedin.com",      # Professional networking
    "amazon.com",        # E-commerce platform
    "github.com",        # Code hosting and version control
    "microsoft.com",     # Technology company
    "apple.com",         # Technology company
    "wikipedia.org",     # Online encyclopedia
    "youtube.com",       # Video sharing platform
    "yahoo.com",         # Search engine and services
    "reddit.com",        # Online discussion platform
    "zoom.us",           # Video conferencing platform
    "dropbox.com",       # Cloud storage service
    "slack.com",         # Collaboration software
    "paypal.com",        # Online payment platform
    "ebay.com",          # E-commerce platform
    "spotify.com",       # Music streaming platform
    "vimeo.com",         # Video sharing platform
    "twitch.tv",         # Video game streaming platform
    "airbnb.com",        # Short-term lodging service
    "netflix.com",       # Video streaming service
    "etsy.com",          # E-commerce platform for handmade goods
    "wordpress.com",     # Content management system
    "shopify.com",       # E-commerce platform
    "tiktok.com",        # Social media platform for short videos
    "tumblr.com",        # Blogging and social networking site
    "cnn.com",           # News website
    "bbc.com",           # News website
    "nytimes.com",       # News website
    "forbes.com",        # Business and financial news
    "businessinsider.com", # Business news
    "theguardian.com",   # News website
    "weather.com",       # Weather forecasting
    "trivago.com",       # Travel and hotel booking
    "expedia.com",       # Travel and hotel booking
    "booking.com",       # Travel and hotel booking
    "chegg.com",         # Educational services
    "quizlet.com",       # Learning platform
    "edx.org",           # Online courses and educational resources
    "coursera.org",      # Online courses
    "udemy.com",         # Online learning platform
    "craigslist.org",    # Classified ads website
    "gravatar.com",      # Avatar service (by WordPress)
    "flickr.com",        # Photo sharing service
    "soundcloud.com",    # Music streaming service
    "t.me",              # Telegram messaging service
    "wikimedia.org",     # Online content hosting platform (Wikimedia)
    "bitbucket.org",     # Code hosting and version control (by Atlassian)
    "asana.com",         # Project management software
    "notion.so",         # Note-taking and collaboration platform
    "trello.com",        # Project management tool
    "jira.com",          # Project tracking and management (by Atlassian)
    "discord.com",       # Communication platform for gamers and communities
    "zoom.com",          # Video conferencing platform
    "salesforce.com",    # Customer relationship management (CRM)
    "atlassian.com",     # Software development and collaboration tools
    "moodle.org",        # Learning management system (LMS)
    "cloudflare.com",    # Internet security, CDN services
    "aws.amazon.com",    # Amazon Web Services (cloud computing)
    "azure.microsoft.com", # Microsoft Azure (cloud computing)
    "heroku.com",        # Platform as a service (PaaS)
    "firebase.google.com", # Mobile and web application development platform (by Google)
]

def user_logout(request):
    logout(request)  # Logs out the user
    request.session.flush()  # Clears all session data
    return redirect("welcome")  # Redirects to the home page


def scan(request):
    if not request.user.is_authenticated:
        messages.warning(request, "⚠️ You must be logged in to scan website!")
        return redirect('welcome')  # Redirect to the homepage (or any page you want)
    
    if request.method == 'POST':
        url = request.POST.get('url')
        
        # Check if the URL is in the whitelist of trusted domains
        for domain in safe_domains:
            if domain in url.lower():
                status = "Safe"
                return render(request, 'detection/result.html', {'url': url, 'status': status})

        # If the URL is not in the whitelist, check if it matches any phishing patterns
        status = "Safe"
        for pattern in phishing_patterns:
            if re.search(pattern, url):
                status = "Unsafe"
                break
        
        # Render the result page with the URL and its status
        return render(request, 'detection/result.html', {'url': url, 'status': status})
    
    # If the request method is not POST, redirect to the home page
    return HttpResponseRedirect('/')

def result(request):
    return render(request, 'detection/result.html')



def upload_email(request):
    if not request.user.is_authenticated:
        messages.warning(request, "⚠️ You must be logged in to check your email")
        return redirect('welcome')  # Redirect to the homepage (or any page you want)
    
    result = None
    if request.method == "POST":
        email_body = request.POST.get("email_body", "")
        sender_email = request.POST.get("sender_email", "")
        email_attachments = request.FILES.getlist("email_attachments")

        if email_body and sender_email:
            result = detect_fraudulent_email(email_body, sender_email, email_attachments)

    return render(request, "detection/email_form.html", {"result": result})

from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def signup(request):
    if request.method == 'POST':
        try:
            print("Request Headers:", request.headers)
            print("Request Body:", request.body)

            if request.content_type == "application/json":
                data = json.loads(request.body)
                full_name = data.get('full_name')
                email = data.get('email')
                password = data.get('password')
                confirm_password = data.get('confirm_password')
            else:
                full_name = request.POST.get('full_name')
                email = request.POST.get('email')
                password = request.POST.get('password')
                confirm_password = request.POST.get('confirm_password')

            # Print password values for debugging
            print(f"Password: {password}, Confirm Password: {confirm_password}")

            if not full_name or not email or not password:
                return JsonResponse({'error': 'All fields are required'}, status=400)

            if password.strip() != confirm_password.strip():
                return JsonResponse({'error': 'Passwords do not match'}, status=400)

            if User.objects.filter(username=full_name).exists():
                return JsonResponse({'error': 'Username already exists, try another'}, status=400)

            if User.objects.filter(email=email).exists():
                return JsonResponse({'error': 'Email already registered, please login'}, status=400)

            user = User(username=full_name, email=email, password=make_password(password))
            user.save()

            # Automatically log in the new user
            login(request, user)

            # Set session expiry (keeps user logged in)
            request.session.set_expiry(1209600)  # 2 weeks

            return redirect('welcome')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
    return JsonResponse({'error': 'Invalid request'}, status=400)




@csrf_exempt
def signin(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body) if request.content_type == "application/json" else request.POST
            username_or_email = data.get('username')
            password = data.get('password')

            if not username_or_email or not password:
                return JsonResponse({'error': 'Username and password required'}, status=400)

            # Check if user entered an email
            user = None
            if '@' in username_or_email:
                try:
                    user_obj = User.objects.get(email=username_or_email)
                    username_or_email = user_obj.username  # Convert email to username
                except User.DoesNotExist:
                    return JsonResponse({'error': 'No user with this email'}, status=400)

            # Authenticate user
            user = authenticate(request, username=username_or_email, password=password)

            if user is not None:
                login(request, user)
                request.session.set_expiry(1209600)  # ✅ Keeps user logged in for 2 weeks
                messages.success(request, f'Welcome, {user.username}!')
                return redirect('welcome')  # ✅ Redirects to home page
            else:
                messages.error(request, 'Invalid credentials')
                return JsonResponse({'error': 'Invalid username or password'}, status=400)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)

    return JsonResponse({'error': 'Invalid request'}, status=400)

from django.views.decorators.csrf import csrf_exempt

def user_logout(request):
    logout(request)  # Logs out the user
    return redirect('welcome')  # Redirect to home page after logout

@csrf_exempt
def save_user(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user, created = User.objects.get_or_create(
                username=data["email"],  # Using email as username
                defaults={"first_name": data["name"], "email": data["email"]}
            )
            return JsonResponse({"message": "User saved", "created": created})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({"error": "Invalid request"}, status=400)



from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import numpy as np
import cv2
from pyzbar.pyzbar import decode

@csrf_exempt
def scan_qr1(request):
    
    
    # result = None

    if request.method == 'POST' and request.FILES.get('qr_image'):
        qr_image = request.FILES['qr_image']

        # Read and convert image to numpy array
        image_data = np.asarray(bytearray(qr_image.read()), dtype=np.uint8)
        image = cv2.imdecode(image_data, cv2.IMREAD_COLOR)

        if image is None:
            return JsonResponse({'error': 'Could not read image'}, status=400)

        # Decode QR code from image
        decoded_objects = decode(image)

        if not decoded_objects:
            # Try grayscale (sometimes works better)
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            decoded_objects = decode(gray)

        if not decoded_objects:
            return JsonResponse({'error': 'No QR code found'}, status=400)

        # Get the first QR code's data
        qr_data = decoded_objects[0].data.decode("utf-8")

        return JsonResponse({
            'url': qr_data,
            'status': "QR code detected successfully"
        })

    return JsonResponse({'error': 'Invalid request'}, status=400)
