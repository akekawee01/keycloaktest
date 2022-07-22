from django.shortcuts import redirect, render
#####################
from django.contrib.auth.models import User
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST
from rest_framework.response import Response
import requests
from django.http import HttpResponseRedirect
from django.utils.crypto import get_random_string
from rest_framework.decorators import api_view,permission_classes
from rest_framework.permissions import AllowAny
import base64
import json
import os
from dotenv import load_dotenv
load_dotenv()
############################# Redirect URL ###########################
@api_view(['GET'])
@permission_classes((AllowAny,))
def redirectToKeycloak(request):
    init_state = get_random_string(32)
    url = ''
    url += os.getenv('Keycloak_Auth_Url') 
    url += '?response_type=code'
    url += '&scope=openid+email+profile'
    url += '&client_id=' + os.getenv('Keycloak_Client_Id') 
    url += '&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback'
    url += '&state='+init_state
    request.session['init_state'] = init_state
    return HttpResponseRedirect(url)
############################# Token Generate  ###########################
@api_view(['GET'])
@permission_classes((AllowAny,))
def sso_token(request):
    try:
        if request.GET.get("state") == request.session['init_state']:

            url_token = os.getenv('Keycloak_Token_Url')

            headers_token = {
                    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",           
                        }
            payload_token='code='+ str(request.GET.get("code")) +'&client_id='+ os.getenv('Keycloak_Client_Id')  +'&client_secret='+ os.getenv('Keycloak_Client_Secret') +'&grant_type=authorization_code&redirect_uri=http://localhost:8000/callback'

            response_token = requests.request(
                "POST", url_token, data=payload_token, headers=headers_token)
            
            if response_token.status_code == 200 :
               
                response_token = response_token.json()
                print(response_token)
                id_token_payload = response_token['id_token'].split('.')
                idt_payload_decoded = base64.b64decode(id_token_payload[1] + '=' * (4 - len(id_token_payload[1]) % 4)).decode('utf-8')
                json_idt = json.loads(idt_payload_decoded)

                if json_idt['iss'] == os.getenv("Keycloak_Issuer") and json_idt['aud'] == os.getenv('Keycloak_Client_Id'):
                    url_info = os.getenv('Keycloak_Userinfo_Url')
                        
                    headers_info = {
                            "Authorization": "Bearer " + response_token['access_token'],
                                        
                                }
                    payload_info = {
                        ##### Blank #####
                                }
                    response_info = requests.request(
                            "GET", url_info,json=payload_info, headers=headers_info)

                    response_info = response_info.json()        
                    print(response_info)
                    if response_info['sub'][0:2] == "f:" : #  check if be PEA employee or not
                        
                    # if User.objects.filter(username=response_info['preferred_username']).exists():      #Check if User in Your DB
                        response = redirect('http://localhost:8000/nopage')                  
                        response.set_cookie('msg', 'success', max_age=1000)
                        response.set_cookie('user', response_info['preferred_username'], max_age=1000)
                        response.set_cookie('token',"your_system_token", max_age=1000)
                        return response
                else:
                    msg = {"msg" : "iss_or_aud_mistake"}
                    return Response(msg, status=HTTP_400_BAD_REQUEST)         

            else:
                msg = {"msg" : "code_not_correct"}
                return Response(msg, status=HTTP_400_BAD_REQUEST) 
            
        else:
            msg = {"msg" : "state_not_corrects"}
            return Response(msg, status=HTTP_400_BAD_REQUEST) 


    except ValueError as e:
        return Response(e.args[0], status=HTTP_400_BAD_REQUEST)
############################# Logout ###########################
@api_view(['GET'])
@permission_classes((AllowAny,))
def provider_logout(request):
    
    return HttpResponseRedirect(os.getenv('Keycloak_Logout_Url'))

