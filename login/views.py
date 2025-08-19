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
            user = Authentication.objects.filter(email=email).first()
            
            if user and check_password(password, user.password):
                access_payload = {
                    "email": user.email,
                    "user_id":user.id,
                    "iat": int(datetime.now(timezone.utc).timestamp()),
                    "exp": int((datetime.now(timezone.utc) + timedelta(minutes=20)).timestamp())
                } 
                access_token = jwt_instance.encode(
                    payload=access_payload,
                    key=jwk_key,
                    alg="HS256",
                    optional_headers={"typ": "JWT"}
                )
                refresh_payload = {
                    "email":user.email,
                    "user_id":user.id,
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

@csrf_exempt
def Refresh_token(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            refresh_token = data.get('refresh_token')
            if not refresh_token:
                return JsonResponse({'error': 'Refresh token is required'}, status=400)
            try:
                decode = jwt_instance.decode(refresh_token, jwk_key, do_verify=True)
            except Exception as e:
                return JsonResponse({'error': f'Invalid or expired refresh token: {e}'}, status=401)
            
            new_access_payload ={
                "email": decode['email'],
                "user_id":decode['user_id'],
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "exp": int((datetime.now(timezone.utc) + timedelta(minutes=20)).timestamp())
            }
            new_access_token = jwt_instance.encode(
                payload=new_access_payload,
                key=jwk_key,
                alg="HS256",
                optional_headers={"typ": "JWT"}
            )
            return JsonResponse({
                'message': 'New access token created successfully',
                'access_token': new_access_token
            })
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
    return JsonResponse({'error':'Only POST method allowed'}, status=405)

@csrf_exempt
def GetUserDetails(request, pk=None):
    if request.method == 'GET':
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return JsonResponse({"error": "Authorization header missing or invalid"}, status=401)
        token = auth_header.split(" ")[1]
        try:
            decoded = jwt_instance.decode(token, jwk_key, do_verify=True)
        except Exception as e:
            return JsonResponse({"error": f"Invalid or expired token: {e}"}, status=401)
        if str(decoded.get("user_id")) !=str(pk):
            return JsonResponse({"error": "Token does not match the requested user ID"}, status=403)
        try:
            user = Authentication.objects.get(pk=pk)
            return JsonResponse({
                'name': user.name,
                'email': user.email,
                'gender': user.gender
            })
        except Authentication.DoesNotExist:
            return JsonResponse({"message":"The user does not exist"}, status=404)
    return JsonResponse({"message":"Only GET method is allowed"}, status=405)

 

            
    

