from django.http import HttpResponse,JsonResponse
import json
from django.views.decorators.csrf import csrf_exempt
from .models import Authentication
from django.contrib.auth.hashers import make_password,check_password
import re
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from jwt import JWT
from jwt.jwk import OctetJWK
from datetime import timedelta,datetime,timezone

secret_key = "TGDYIUHKSJUGDYBUISBYVDY"
jwk_key = OctetJWK(secret_key.encode())

# Create JWT instance
jwt_instance = JWT()
# Create your views here.
def home(request):
    return HttpResponse("Hello all")
@csrf_exempt
def signup(request):
    if request.method=='POST':
        try:
            data=json.loads(request.body)
            name=data.get('name')
            email=data.get('email')
            password=data.get('password')
            gender=data.get('gender')
            if not all([name,email,password,gender]):
                return JsonResponse({'error': 'Missing required fields'}, status=400)
            if Authentication.objects.filter(email=email).exists():
                return JsonResponse({'error': 'This email already exists'}, status=400)
            
            email_validate = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_validate, email):
                return JsonResponse({'error': 'Invalid email format'}, status=400)
            
            try:
                validate_password(password)
            except ValidationError as ve:
                return JsonResponse({'error': ve.messages}, status=400)
            
            hash_password=make_password(password)
            user = Authentication.objects.create(name=name, email=email, password=hash_password, gender=gender)
            return JsonResponse({'message':'signup process completed','userid': user.id,'status':'201'},status=201)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON','status':'400'}, status=400)
    else:
        return JsonResponse({'error': 'Only POST method allowed','status':'405'},status=405)

@csrf_exempt
def login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')
            if not all([email, password]):
                return JsonResponse({'error': 'Email and password are required'}, status=400)
            user = Authentication.objects.filter(email=email,).first()
            
            # Define payload
            if user and check_password(password, user.password):
                access_payload = {
                    "email": user.email,
                    "iat": int(datetime.now(timezone.utc).timestamp()),
                    "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
                }
                # Encode token
                access_token = jwt_instance.encode(
                    payload=access_payload,
                    key=jwk_key,
                    alg="HS256",
                    optional_headers={"typ": "JWT"}
                )
                refresh_payload = {
                    "email":user.email,
                    "iat": int(datetime.now(timezone.utc).timestamp()),
                    "exp": int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp())
                }
                refresh_token=jwt_instance.encode(
                    payload=refresh_payload,
                    key=jwk_key,
                    alg="HS256",
                    optional_headers={"typ":"JWT"}
                )
                return JsonResponse({'message':'login process completed','access_token':access_token,'refresh_token':refresh_token,'userid':user.id})
            else:
                return JsonResponse({'error': 'Invalid credentials','status id':'401'}, status=401)        
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON','status id':'400'}, status=400)
    else:
        return JsonResponse({'error': 'Only POST method allowed','status id':'405'}, status=405)


                
        
    


  


            

            
    

