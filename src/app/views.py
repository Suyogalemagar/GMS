from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render,redirect,get_object_or_404
from django.contrib.auth import authenticate, logout, login
from .models import *
from .forms import *
from random import randint

# Create your views here.
def index(request):
    if request.method == "POST":
        u = request.POST['uname']
        p = request.POST['pwd']
        user = authenticate(username=u, password=p)
        if user:
            if user.is_staff:
                login(request, user)
                messages.success(request, "Logged In Successfully")
                return redirect('admin_base')
            else:
                messages.success(request, "Invalid Credentials, Please try again")
                return redirect('index')
    package = Package.objects.filter().order_by('id')[:5]
    return render(request, 'index.html', locals())

def registration(request):
    if request.method == "POST":
        fname = request.POST['firstname']
        lname = request.POST['lastname']
        email = request.POST['email']
        pwd = request.POST['password']
        mobile = request.POST['mobile']
        address = request.POST['address']

        user = User.objects.create_user(first_name=fname, last_name=lname, email=email, password=pwd, username=email,is_active=0)
        Signup.objects.create(user=user, mobile=mobile,address=address)
        messages.success(request, "Register Successful")
        return redirect('user_login')
    return render(request, 'registration.html', locals())

def user_login(request):
    if request.method == "POST":
        email = request.POST['email']
        pwd = request.POST['password']
        user = authenticate(username=email, password=pwd)
        if user:
            if user.is_active == 0:
                messages.error(request, "Account not verified")
            elif user.is_staff:
                messages.error(request, "Invalid User")
                return redirect('user_login')
            else:
                login(request, user)
                messages.success(request, "User Login Successful")
                return redirect('index')
        else:
            messages.error(request, "Invalid credentials")
            return redirect('user_login')
    return render(request, 'user_login.html')



def Logout(request):
    logout(request)
    messages.success(request, "Logout Successfully")
    return redirect('index')

def user_logout(request):
    logout(request)
    messages.success(request, "Logout Successfully")
    return redirect('index')



def user_profile(request):
    if request.method == "POST":
        # Get form data
        fname = request.POST.get('firstname')
        lname = request.POST.get('secondname')
        email = request.POST.get('email')
        mobile = request.POST.get('mobile')
        address = request.POST.get('address')
        
        # Update User model
        User.objects.filter(id=request.user.id).update(
            first_name=fname,
            last_name=lname,
            
        )
        
        # Get or create Signup instance
        signup_instance = Signup.objects.get(user=request.user)
        
        # Update fields
        signup_instance.mobile = mobile
        signup_instance.address = address
        
        # Handle file upload
        if 'profile_pic' in request.FILES:
            
            if signup_instance.profile_pic:
                signup_instance.profile_pic.delete()
            signup_instance.profile_pic = request.FILES['profile_pic']
        
        signup_instance.save()
        
        messages.success(request, "Profile updated successfully!")
        return redirect('user_profile')
    
    try:
        data = Signup.objects.get(user=request.user)
    except Signup.DoesNotExist:
        data = Signup.objects.create(user=request.user)
    
    return render(request, "user_profile.html", {'data': data})


def user_change_password(request):
    if request.method=="POST":
        n = request.POST['pwd1']
        c = request.POST['pwd2']
        o = request.POST['pwd3']
        if c == n:
            u = User.objects.get(username__exact=request.user.username)
            u.set_password(n)
            u.save()
            messages.success(request, "Password changed successfully")
            return redirect('/')
        else:
            messages.success(request, "New password and confirm password are not same.")
            return redirect('user_change_password')
    return render(request,'user_change_password.html')

def manageCategory(request):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    category = Category.objects.all()
    try:
        if request.method == "POST":
            categoryname = request.POST['categoryname']

            try:
                Category.objects.create(categoryname=categoryname)
                error = "no"
            except:
                error = "yes"
    except:
        pass
    return render(request, 'admin/manageCategory.html', locals())

def editCategory(request, pid):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    error = ""
    category = Category.objects.get(id=pid)
    if request.method == "POST":
        categoryname = request.POST['categoryname']

        category.categoryname = categoryname

        try:
            category.save()
            error = "no"
        except:
            error = "yes"
    return render(request, 'admin/editCategory.html', locals())

def deleteCategory(request, pid):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    category = Category.objects.get(id=pid)
    category.delete()
    return redirect('manageCategory')

@login_required(login_url='/admin_login/')
def reg_member(request):
    data = Signup.objects.all()
    print(data)
    d = {'data': data}
    return render(request, "admin/reg_member.html", locals())


@login_required(login_url='/admin_login/')
def delete_user(request, pid):
    data = Signup.objects.get(id=pid)
    data.delete()
    messages.success(request, "Delete Successful")
    return redirect('reg_member')

@login_required(login_url='/admin_login/')
def reg_trainer(request):
    data = Signup.objects.all()
    d = {'data': data}
    return render(request, "admin/reg_trainer.html", locals())

@login_required(login_url='/admin_login/')
def delete_user(request, pid):
    data = Signup.objects.get(id=pid)
    data.delete()
    messages.success(request, "Delete Successful")
    return redirect('reg_trainer')

def managePackageType(request):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    package = Packagetype.objects.all()
    category = Category.objects.all()
    try:
        if request.method == "POST":
            cid = request.POST['category']
            categoryid = Category.objects.get(id=cid)

            packagename = request.POST['packagename']

            try:
                Packagetype.objects.create(category=categoryid, packagename=packagename)
                error = "no"
            except:
                error = "yes"
    except:
        pass
    return render(request, 'admin/managePackageType.html', locals())

def editPackageType(request, pid):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    category = Category.objects.all()
    package = Packagetype.objects.get(id=pid)
    if request.method == "POST":
        cid = request.POST['category']
        categoryid = Category.objects.get(id=cid)
        packagename = request.POST['packagename']

        package.category = categoryid
        package.packagename = packagename

        try:
            package.save()
            error = "no"
        except:
            error = "yes"
    return render(request, 'admin/editPackageType.html', locals())


def deletePackageType(request, pid):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    package = Packagetype.objects.get(id=pid)
    package.delete()
    return redirect('managePackageType')

def addPackage(request):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    category = Category.objects.all()
    packageid = request.GET.get('packagename', None)
    mypackage = None
    if packageid:
        mypackage = Packagetype.objects.filter(packagename=packageid)
    if request.method == "POST":
        cid = request.POST['category']
        categoryid = Category.objects.get(id=cid)
        packagename = request.POST['packagename']
        packageobj = Packagetype.objects.get(id=packagename)
        titlename = request.POST['titlename']
        duration = request.POST['duration']
        price = request.POST['price']
        description = request.POST['description']

        try:
            Package.objects.create(category=categoryid,packagename=packageobj,
                                   titlename=titlename, packageduration=duration,price=price,description=description)
            error = "no"
        except:
            error = "yes"
    mypackage = Packagetype.objects.all()
    return render(request, 'admin/addPackage.html',locals())

def managePackage(request):
    package = Package.objects.all()
    return render(request, 'admin/managePackage.html',locals())


from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth.decorators import login_required

from django.shortcuts import render, redirect
from django.contrib import messages

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib import messages

def admin_login(request):
    if request.method == 'POST':
        # Get the username and password from the form
        username = request.POST.get('uname')
        password = request.POST.get('pwd')

        # Authenticate the user using the Django authentication system
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # If the user exists and credentials are correct, log the user in
            login(request, user)
            messages.success(request, "Login successful! Welcome back!")
            return redirect('admin_home')  # Redirect to the admin home page
        else:
            # If authentication fails, show an error message
            messages.error(request, "Invalid username or password.")
            return redirect('adminlogin')  # Stay on the login page

    return render(request, 'admin_login.html')


@login_required
def admin_home(request):
    # This page is accessible only by logged-in users with the 'is_staff' flag
    return render(request, 'admin/admin_home.html')


@login_required(login_url='/user_login/')
def enrolled_history(request):
    data = Signup.objects.get(user=request.user)
    data = Enroll.objects.filter(register=data)
    return render(request, "enrolled_history.html", locals())

@login_required(login_url='/admin_login/')
def new_enroll(request):
    action = request.GET.get('action')
    data = Enroll.objects.all()

    if action == "New":
        data = data.filter(status="1")
    elif action == "Total":
        pass

    if request.user.is_staff:
        return render(request, "admin/new_enroll.html", locals())
    else:
        return render(request, "enrolled_history.html", locals())

def enrolled_detail(request, pid):
    data = Enroll.objects.get(id=pid)
    if request.method == "POST":
        price = request.POST['price']
        status = request.POST['status']
        data.status = status
        data.save()
        Paymenthistory.objects.create(enroll=data, price=price, status=status)
        messages.success(request, "Action Updated")
        return redirect('enrolled_detail', pid)
    payment = Paymenthistory.objects.filter(enroll=data)
    if request.user.is_staff:
        return render(request, "admin/admin_enrolled_detail.html", locals())
    else:
        return render(request, "user_enrolled_detail.html", locals())

def editPackage(request, pid):
    category = Category.objects.all()
    if request.method == "POST":
        cid = request.POST['category']
        categoryid = Category.objects.get(id=cid)
        packagename = request.POST['packagename']
        packageobj = Packagetype.objects.get(id=packagename)
        titlename = request.POST['titlename']
        duration = request.POST['duration']
        price = request.POST['price']
        description = request.POST['description']

        Package.objects.filter(id=pid).update(category=categoryid,packagename=packageobj,
                                   titlename=titlename, packageduration=duration,price=price,description=description)
        messages.success(request, "Updated Successful")
        return redirect('managePackage')
    data = Package.objects.get(id=pid)
    mypackage = Packagetype.objects.all()
    return render(request, "admin/editPackage.html", locals())

def load_subcategory(request):
    categoryid = request.GET.get('category')
    subcategory = Package.objects.filter(category=categoryid).order_by('PackageName')
    return render(request,'subcategory_dropdown_list_options.html',locals())

def deletePackage(request, pid):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    package = Package.objects.get(id=pid)
    package.delete()
    return redirect('managePackage')

def deleteenrolled(request, pid):
    Enroll = Enroll.objects.get(id=pid)
    Enroll.delete()
    messages.success(request, "Delete Successful")
    return redirect('new_enrolled')

def enrolledReport(request):
    data = None
    data2 = None
    if request.method == "POST":
        fromdate = request.POST['fromdate']
        todate = request.POST['todate']

        data = Enroll.objects.filter(creationdate__gte=fromdate, creationdate__lte=todate)
        data2 = True
    return render(request, "admin/enrolledReport.html", locals())

def regReport(request):
    data = None
    data2 = None
    if request.method == "POST":
        fromdate = request.POST['fromdate']
        todate = request.POST['todate']

        data = Signup.objects.filter(creationdate__gte=fromdate, creationdate__lte=todate)
        data2 = True
    return render(request, "admin/regReport.html", locals())


def changePassword(request):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    error = ""
    user = request.user
    if request.method == "POST":
        o = request.POST['oldpassword']
        n = request.POST['newpassword']
        try:
            u = User.objects.get(id=request.user.id)
            if user.check_password(o):
                u.set_password(n)
                u.save()
                error = "no"
            else:
                error = 'not'
        except:
            error = "yes"
    return render(request, 'admin/changePassword.html',locals())

def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)

# @login_required(login_url='/user_login/')
# def Enroll(request):
#     Enroll = None
#     enrolleded = Enroll.objects.filter(register__user=request.user)
#     enrolleded_list = [i.policy.id for i in enrolleded]
#     data = Package.objects.filter().exclude(id__in=enrolleded_list)
#     if request.method == "POST":
#         Enroll = Package.objects.filter()
#         Enroll = enrolledForm(request.POST, request.FILES, instance=Enroll)
#         if Enroll.is_valid():
#             Enroll = Enroll.save()
#             Enroll.enrollednumber = random_with_N_digits(10)
#             data.Enroll = Enroll
#             data.save()
#         Enroll.objects.create(package=Enroll)
#         messages.success(request, "Action Updated")
#         return redirect('Enroll')
#     return render(request, "/", locals())

@login_required(login_url='/user_login/')
def apply_enrolled(request, pid):
    package = get_object_or_404(Package, id=pid)
    register = get_object_or_404(Signup, user=request.user)

    enrollment = Enroll.objects.create(
        package=package,
        register=register,
        enrollnumber=random_with_N_digits(10)
    )

    messages.success(request, 'Enroll Applied')
    
    payment_url = reverse('payment_view')

    context = {
      'action_url': payment_url,
        'enrolled_id': enrollment.id,
        'amount': package.price,
    }

    # Return an HttpResponse with a hidden form for POST redirect
    return render(request, 'hidden_post_form.html', context)
from django.shortcuts import render, redirect
from django.http import HttpResponseBadRequest, JsonResponse
from django.urls import reverse
from django.conf import settings
from django.contrib.auth.models import User
from .models import Payment, Paymenthistory, Enroll, Signup
import uuid
import hashlib
import base64
import hmac

# Function to generate the signature for eSewa
def generate_signature(amount, transaction_uuid, product_code, secret):
    hash_string = f"total_amount={amount},transaction_uuid={transaction_uuid},product_code={product_code}"
    secret_bytes = secret.encode('utf-8')
    hash_string_bytes = hash_string.encode('utf-8')
    hmac_sha256 = hmac.new(secret_bytes, hash_string_bytes, hashlib.sha256)
    digest = hmac_sha256.digest()
    signature = base64.b64encode(digest).decode('utf-8')
    return signature

def payment_view(request):
    if request.method == 'POST':
        amount = float(request.POST.get('amount'))
        full_name = request.POST.get('full_name')
        phone_number = request.POST.get('phone_number')
        enrolled_id = request.POST.get("enrolled_id")

        transaction_uuid = str(uuid.uuid4())
        secret = settings.ESEWA_SECRET_KEY

        tax_amount = 0
        service_charge = 0
        delivery_charge = 0
        total_amount = amount + tax_amount + service_charge + delivery_charge

        signature = generate_signature(total_amount, transaction_uuid, "EPAYTEST", secret)

        user = request.user
        enrollment = Enroll.objects.get(id=enrolled_id)

        # Save to Payment model
        payment = Payment.objects.create(
            user=user,
            enroll=enrollment,
            transaction_uuid=transaction_uuid,
            amount=total_amount,
            signature=signature,
            success_url=request.build_absolute_uri(reverse('payment_success')),
            failure_url=request.build_absolute_uri(reverse('payment_failure')),
        )

        # Save to Paymenthistory model
        signup_user = Signup.objects.get(user=user)
        Paymenthistory.objects.create(
            user=signup_user,
            enroll=enrollment,
            price=total_amount,
            status=1  # Assuming 1 = Paid
        )

        # Data to send to eSewa
        esewa_data = {
            'amount': payment.amount,
            'tax_amount': tax_amount,
            'total_amount': total_amount,
            'transaction_uuid': payment.transaction_uuid,
            'product_code': "EPAYTEST",
            'product_service_charge': service_charge,
            'product_delivery_charge': delivery_charge,
            'success_url': payment.success_url,
            'failure_url': payment.failure_url,
            'signature': payment.signature,
            'signed_field_names': "total_amount,transaction_uuid,product_code",
            'full_name': full_name,
            'phone_number': phone_number,
        }

        return render(request, 'payment/payment_form.html', esewa_data)

    return render(request, 'payment/payment_form.html')

def payment_success(request):
    # Get the latest payment for the current user
    try:
        payment = Payment.objects.filter(user=request.user).latest('creationdate')
        enrollment = payment.enroll
        package = enrollment.package
        
        # Prepare email content
        subject = f'Payment Confirmation for {package.titlename}'
        
        context = {
            'member_name': f"{request.user.first_name} {request.user.last_name}",
            'package_name': package.titlename,
            'amount': payment.amount,
            'transaction_date': payment.creationdate.strftime("%B %d, %Y %H:%M"),
            'expiry_date': enrollment.expiry_date.strftime("%B %d, %Y") if hasattr(enrollment, 'expiry_date') else "N/A",
        }
        
        # Render HTML content
        html_message = render_to_string('paymentsuccessemail.html', context)
        plain_message = strip_tags(html_message)
        
        # Send email
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[request.user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        # Update payment status if needed
        payment.status = 1  # Paid
        payment.save()
        
    except Exception as e:
        # Log error but don't show to user
        print(f"Error sending confirmation email: {e}")
    
    return render(request, 'payment/payment_success.html')

def payment_failure(request):
    return render(request, 'payment/payment_failure.html')

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib import messages

from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login

# views.py
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect

def trainer_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        
        if not username or not password:
            messages.error(request, "Username and Password are required.")
            return redirect("trainer_login")

        user = authenticate(request, username=username, password=password)
        
        if user is None:
            messages.error(request, "Invalid username or password.")
            return redirect("trainer_login")
            
        try:
            trainer = Trainer.objects.get(user_id=user.id)
            if not trainer.is_verified:
                messages.error(request, "Account not verified. Please contact admin.")
                return redirect("trainer_login")
            
            login(request, user)
            request.session['show_popup'] = True  # Add this line
            messages.success(request, "Login successful! Welcome back!")
            return redirect("trainer_page")
            
        except Trainer.DoesNotExist:
            messages.error(request, "Trainer account not found.")
            return redirect("trainer_login")

    return render(request, "trainer_login.html")

def trainer_logout(request):
    logout(request)
    messages.success(request, "Logged out successfully!")
    return redirect("trainer_login")
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags

@csrf_exempt
def verify_user(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_id = data.get("user_id")
            choice = data.get("choice", "Yes")  # Get the verification choice
            
            user = User.objects.get(id=user_id)
            
            if choice == "Yes":
                user.is_active = True
                user.save()
                
                # Send verification email
                subject = "Your Account Has Been Verified"
                html_message = render_to_string('accountverifyemail.html', {
                    'user': user,
                    'site_name': "Gym Managament System"  # Change this to your gym's name
                })
                plain_message = strip_tags(html_message)
                from_email = settings.DEFAULT_FROM_EMAIL
                to_email = user.email
                
                send_mail(
                    subject,
                    plain_message,
                    from_email,
                    [to_email],
                    html_message=html_message,
                    fail_silently=False
                )
                
                return JsonResponse({"success": True, "message": "User verified and notification sent"})
            else:
                return JsonResponse({"success": False, "message": "Verification denied"})
                
        except User.DoesNotExist:
            return JsonResponse({"success": False, "error": "User not found"})
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})
    return JsonResponse({"success": False, "error": "Invalid request"})

def get_users(request):
    if request.method == "GET":
        users = Signup.objects.select_related('user').all()
        user_list = [
            {
                "id": user.id,
                "first_name": user.user.first_name,
                "email": user.user.username,
                "mobile": user.mobile,
                "address": user.address,
                "is_active": user.is_active
            }
            for user in users
        ]
        return JsonResponse(user_list, safe=False)

# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User

@csrf_exempt
def delete_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_id = data.get("user_id")
            user = User.objects.get(id=user_id)
            user.delete()
            return JsonResponse({"success": True})
        except User.DoesNotExist:
            return JsonResponse({"success": False, "error": "User not found"})
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})
# views.py
from django.shortcuts import render, redirect
from .models import Trainer
from django.http import JsonResponse

from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib import messages
from .models import Trainer, Signup  
def trainer_registration(request):
    if request.method == "POST":
        fname = request.POST['first_name']
        lname = request.POST['last_name']
        email = request.POST['email']
        password = request.POST['password']
        phone = request.POST['phone']
        address = request.POST['address']
        experience = request.POST.get('experience', '')

        # Check if the username (email) already exists
        if User.objects.filter(username=email).exists():
            messages.error(request, "This email is already registered. Please use a different email.")  # Use messages for error display
            return render(request, 'trainer_reg.html', {'first_name': fname, 'last_name': lname, 'email': email, 'phone': phone, 'address': address, 'experience': experience}) # Re-render the form with the data entered, so the user doesn't have to re-enter everything.

        try:
            user = User.objects.create_user(username=email, email=email, password=password)
            trainer = Trainer.objects.create(
                user=user,
                first_name=fname,
                last_name=lname,
                email=email,
                phone=phone,
                address=address,
                experience=experience
            )
            messages.success(request, "Trainer Registered Successfully")
            return redirect('trainer_login')

        except Exception as e: # Catch any other potential errors during user creation
            messages.error(request, f"Registration failed: {e}")  # Log the error for debugging
            return render(request, 'trainer_reg.html', {'first_name': fname, 'last_name': lname, 'email': email, 'phone': phone, 'address': address, 'experience': experience}) # Re-render the form with the data entered

    return render(request, 'trainer_reg.html') # Render empty form for GET requests
@login_required
def reg_trainer(request):
    trainers = Trainer.objects.all()  # Get all trainers
    return render(request, 'admin/reg_trainer.html', {'trainers': trainers})
from django.views.decorators.http import require_POST
@require_POST
@login_required
def delete_trainer(request, trainer_id):
    try:
        trainer = Trainer.objects.get(id=trainer_id)
        # Delete associated user as well if needed
        user = trainer.user
        trainer.delete()
        user.delete()
        return JsonResponse({"success": True})
    except Trainer.DoesNotExist:
        return JsonResponse({"success": False, "error": "Trainer not found"}, status=404)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)

from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from django.shortcuts import render, redirect
from .models import Trainer



def view_trainer_profile(request, id):  
    print("here")
    trainer = get_object_or_404(Trainer, id=id)
    return render(request, 'Trainers/trainerprofilecard.html', {'trainer': trainer})


@login_required
def trainer_profile(request):
    try:
        trainer = Trainer.objects.get(user=request.user)
    except Trainer.DoesNotExist:
        messages.error(request, "Trainer profile not found")
        return redirect('home')
    
    return render(request, 'Trainers/trainer_profile.html', {'trainer': trainer})



@login_required
def update_trainer_profile(request):
    # Ensure the user has a trainer profile
    if not hasattr(request.user, 'trainer'):
        messages.error(request, "You don't have a trainer profile.")
        return redirect('home')  # Redirect to appropriate page
    
    trainer = request.user.trainer
    
    if request.method == 'POST':
        # Update basic fields with proper fallbacks
        trainer.first_name = request.POST.get('first_name', trainer.first_name)
        trainer.last_name = request.POST.get('last_name', trainer.last_name)
        trainer.phone = request.POST.get('phone', trainer.phone)
        trainer.address = request.POST.get('address', trainer.address)
        trainer.experience = request.POST.get('experience', trainer.experience)
        trainer.profile_url = request.POST.get('profile_url', trainer.profile_url)
        
        # Handle status update - only allow valid choices
        new_status = request.POST.get('status')
        if new_status in dict(trainer.STATUS_CHOICES).keys():
            trainer.status = new_status
        else:
            messages.warning(request, f"Invalid status selected. Keeping current status: {trainer.get_status_display()}")
        
        # Handle file upload
        if 'profile_photo' in request.FILES:
            # Optional: Add file validation here (size, type, etc.)
            trainer.profile_photo = request.FILES['profile_photo']
        
        try:
            trainer.save()
            messages.success(request, 'Profile updated successfully!')
        except Exception as e:
            messages.error(request, f'Error updating profile: {str(e)}')
        
        return redirect('trainer_profile')
    
   
    context = {
        'trainer': trainer,
    }
    return render(request, 'trainer_profile.html', context)

@login_required
def trainer_change_password_page(request):
    return render(request, 'Trainers/trainer_change_password.html')

@login_required
def trainer_change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        user = request.user
        
        if not user.check_password(current_password):
            messages.error(request, "Current password is incorrect")
        elif new_password != confirm_password:
            messages.error(request, "New passwords don't match")
        else:
            user.set_password(new_password)
            user.save()
            update_session_auth_hash(request, user)  # Important to keep user logged in
            messages.success(request, "Password changed successfully")
            return redirect('trainer_profile')
        
        return redirect('trainer_change_password_page')
    
    return redirect('trainer_profile')    
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

@require_POST
@login_required
def verify_trainer(request):
    if request.method != 'POST':
        return JsonResponse({"success": False, "error": "Invalid request method"}, status=400)
    
    trainer_id = request.POST.get('trainer_id')
    
    if not trainer_id:
        return JsonResponse({"success": False, "error": "Trainer ID is required"}, status=400)
        
    try:
        trainer_id = int(trainer_id)
    except ValueError:
        return JsonResponse({"success": False, "error": "Invalid trainer ID format"}, status=400)

    trainer = get_object_or_404(Trainer, user_id=trainer_id)
    
    if not trainer.is_verified:
        trainer.is_verified = True
        trainer.status = 'active'
        trainer.save()
        
        # Prepare email context
        context = {
            'trainer': trainer,
            'site_name': settings.SITE_NAME,
            'login_url': settings.BASE_URL + '/login'  # Add BASE_URL to your settings
        }
        
        # Render HTML content
        html_content = render_to_string('Trainers/trainer_verified.html', context)
        text_content = strip_tags(html_content)  # Fallback text version
        
        # Create email
        subject = f'Your {settings.SITE_NAME} Trainer Account Has Been Verified'
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = [trainer.user.email]
        
        try:
            msg = EmailMultiAlternatives(subject, text_content, from_email, to_email)
            msg.attach_alternative(html_content, "text/html")
            msg.send()
            
            return JsonResponse({
                "success": True,
                "message": f"Trainer {trainer.user.get_full_name()} has been verified and notification sent."
            })
        except Exception as e:
            return JsonResponse({
                "success": True,
                "warning": f"Trainer verified but email could not be sent: {str(e)}"
            })
    else:
        return JsonResponse({
            "success": False,
            "info": f"Trainer {trainer.user.get_full_name()} is already verified."
        })
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import Class, Trainer, Signup

def add_class(request):
    if request.method == "POST":
        name = request.POST.get('name')
        trainer_id = request.POST.get('trainer')
        schedule = request.POST.get('schedule')
        capacity = request.POST.get('capacity')
        member_ids = request.POST.getlist('members')  

        trainer = Trainer.objects.get(id=trainer_id) if trainer_id else None
        members = Signup.objects.filter(id__in=member_ids)  # Get the Signup objects

        if name and schedule and capacity:
            new_class = Class.objects.create(
                name=name,
                trainer=trainer,
                schedule=schedule,
                capacity=capacity
            )
            new_class.members.set(members)  
            messages.success(request, "Class added successfully!")
            return redirect('classlist')
        else:
            messages.error(request, "Please fill all the required fields")
            
            trainers = Trainer.objects.all()
            members = Signup.objects.all()
            return render(request, 'admin/addclasses.html', {'trainers': trainers,'members': members})


    trainers = Trainer.objects.all()
    members = Signup.objects.all()
    return render(request, 'admin/addclasses.html', {'trainers': trainers,'members': members})


def class_list(request):
    classes = Class.objects.all()
    return render(request, 'admin/classlist.html', {'classes': classes})


def edit_class(request, class_id):
    class_instance = get_object_or_404(Class, id=class_id)
    
    if request.method == "POST":
        class_instance.name = request.POST.get('name')
        class_instance.schedule = request.POST.get('schedule')
        class_instance.capacity = request.POST.get('capacity')
        class_instance.save()
        return redirect('admin/class_list')

    return render(request, 'admin/editclass.html', {'class_instance': class_instance})

def delete_class(request, class_id):
    class_obj = Class.objects.get(id=class_id)
    class_obj.delete()
    messages.success(request, "Class deleted successfully!")
    return redirect('classlist')

def trainer_dashboard(request):
    print("hello")
    # Get the trainer associated with the current logged-in user
    try:
        trainer = Trainer.objects.get(user=request.user)
        print("trainer")
        print(trainer.pk)
    except Trainer.DoesNotExist:
        trainer = None  # Handle case when trainer doesn't exist for the user

    # Fetch all classes assigned to this trainer
    classes = Class.objects.filter(trainer_id=trainer.pk)
    print(classes)
    return render(request, 'Trainers/trainer_page.html', {'trainer': trainer, 'classes': classes})

def member_attendance(request):
    query = request.GET.get('q', '')
    members = Signup.objects.filter(user__username__icontains=query) if query else Signup.objects.all()

    if request.method == 'POST':
        member_id = request.POST.get('member_id')
        status = request.POST.get('status')
        if member_id and status:
            member = Signup.objects.get(id=member_id)
            MemberAttendance.objects.create(member=member, status=status)

    context = {
        'members': members,
        'query': query,
    }
    return render(request, 'admin/member_attendance.html', context)

from django.contrib import messages
from django.shortcuts import redirect, get_object_or_404
from .models import  MemberAttendance
import datetime

def mark_attendance(request, member_id, status):
    if request.method == 'POST':
        # Validate status
        valid_statuses = ['Present', 'Absent']
        status = status.capitalize()
        
        if status not in valid_statuses:
            messages.error(request, "Invalid attendance status.")
            return redirect('member_attendance')

        member = get_object_or_404(Signup, id=member_id)
        now = datetime.datetime.now()
        date = now.date()
        time = now.time()

        # Check if member has an active plan
        active_plan = False
        today = date
        
        for enrollment in member.enroll_set.all():  # Assuming related_name='enroll_set'
            duration_days = parse_duration(enrollment.package.packageduration).days
            expiry_date = enrollment.creationdate.date() + timedelta(days=duration_days)
            
            if expiry_date >= today and enrollment.status == 1:  # status == 1 means Paid
                active_plan = True
                break
        
        if not active_plan:
            messages.error(request, f"{member.user.get_full_name()} doesn't have an active paid plan.")
            return redirect('member_attendance')

        # Check for existing entry
        if MemberAttendance.objects.filter(member=member, date=date).exists():
            messages.warning(request, f"{member.user.get_full_name()} is already marked today.")
            return redirect('member_attendance')  

        MemberAttendance.objects.create(
            member=member,
            date=date,
            time=time,
            status=status
        )
        messages.success(request, f"{member.user.get_full_name()} marked as {status}.")
        return redirect('member_attendance')

    messages.error(request, "Invalid request method.")
    return redirect('member_attendance')

def qr_attendance(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        try:
            member = Signup.objects.get(user__username=username)
            today = timezone.now().date()

            # Check for at least one active and paid enrollment
            enrollments = Enroll.objects.filter(register=member)
            has_valid_plan = False

            for enroll in enrollments:
                duration_days = parse_duration(enroll.package.packageduration).days
                expiry_date = enroll.creationdate.date() + timedelta(days=duration_days)

                if expiry_date >= today and enroll.status == 1:  # status == 1 means Paid
                    has_valid_plan = True
                    break

            if not has_valid_plan:
                messages.error(request, f"{username} does not have an active and paid plan. Attendance not marked.")
                return redirect('qr_attendance')

            # Mark attendance
            MemberAttendance.objects.create(
                member=member,
                date=today,
                time=timezone.now().time(),
                status="Present"
            )

            messages.success(request, f"Attendance marked Present for {username}!")
            return redirect('qr_attendance')

        except Signup.DoesNotExist:
            messages.error(request, f"No member found with username {username}.")
            return redirect('qr_attendance')

    return render(request, 'qr_attendance.html')

from django.shortcuts import render
from .models import MemberAttendance
from django.db.models import Q

def attendance_report(request):
    query = request.GET.get('q')
    if query:
        member_attendance = MemberAttendance.objects.filter(
            Q(member__user__first_name__icontains=query) |
            Q(member__user__last_name__icontains=query) |
            Q(member__user__email__icontains=query)
        ).order_by('-date', '-time')
    else:
        member_attendance = MemberAttendance.objects.all().order_by('-date', '-time')

    return render(request, 'admin/attendance_report.html', {
        'member_attendance': member_attendance,
        'query': query
    })


from django.shortcuts import render, redirect
from django.core.mail import EmailMultiAlternatives
from django.contrib import messages
from app.models import Signup, Trainer
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

def send_notification(request):
    if request.method == "POST":
        subject = request.POST.get('subject', '').strip()
        message = request.POST.get('message', '').strip()
        recipient_type = request.POST.get('recipient_type')
        specific_email = request.POST.get('specific_email', '').strip()

        # Validate required fields
        if not subject:
            messages.error(request, "Subject is required.")
            return redirect('send_notification')
        if not message:
            messages.error(request, "Message content is required.")
            return redirect('send_notification')

        emails = set()

        try:
            if recipient_type == "members":
                emails.update(
                    m.user.email for m in Signup.objects.select_related('user')
                    .filter(user__email__isnull=False)
                    .exclude(user__email='')
                )
            elif recipient_type == "trainers":
                emails.update(
                    t.email for t in Trainer.objects.filter(
                        email__isnull=False
                    ).exclude(email='')
                )
            elif recipient_type == "both":
                emails.update(
                    m.user.email for m in Signup.objects.select_related('user')
                    .filter(user__email__isnull=False)
                    .exclude(user__email='')
                )
                emails.update(
                    t.email for t in Trainer.objects.filter(
                        email__isnull=False
                    ).exclude(email='')
                )
            elif recipient_type == "specific":
                if not specific_email:
                    messages.error(request, "Please provide an email address for specific recipient.")
                    return redirect('send_notification')
                try:
                    validate_email(specific_email)
                    emails.add(specific_email)
                except ValidationError:
                    messages.error(request, "Please enter a valid email address.")
                    return redirect('send_notification')
            else:
                messages.error(request, "Invalid recipient type selected.")
                return redirect('send_notification')

            if not emails:
                messages.warning(request, "No valid recipients found.")
                return redirect('send_notification')

            # Send email
            email_list = list(emails)
            html_message = render_to_string('admin/notification.html', {
                'subject': subject,
                'message': message,
                'site_name': getattr(settings, 'SITE_NAME', 'Our Gym')
            })
            
            email = EmailMultiAlternatives(
                subject,
                strip_tags(html_message),
                settings.DEFAULT_FROM_EMAIL,
                [],
                bcc=email_list,
            )
            email.attach_alternative(html_message, "text/html")
            email.send(fail_silently=False)
            
            messages.success(
                request, 
                f"Email successfully sent to {len(email_list)} recipient(s)."
            )

        except Exception as e:
            messages.error(request, "Failed to send email. Please try again later.")
            if settings.DEBUG:
                print(f"Email error: {str(e)}")

        return redirect('send_notification')

    return render(request, 'admin/send_notification.html')

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Class, Signup, Enroll

@login_required
def member_classes(request):
    try:
        member_profile = get_object_or_404(Signup, user=request.user)
        enrolled_classes = Class.objects.filter(members=member_profile)

        context = {
            'enrolled_classes': enrolled_classes,
            'member': member_profile
        }
        return render(request, 'memberclass.html', context)
    except Exception as e:
        return render(request, 'memberclass.html', {'error': str(e)})


from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from datetime import timedelta
from .models import Signup, Enroll

def parse_duration(duration_str):
    """Convert duration string (like '1 month') to days"""
    try:
        if 'month' in duration_str.lower():
            return 30  # Approximate 1 month as 30 days
        elif 'year' in duration_str.lower():
            return 365  # Approximate 1 year as 365 days
        elif 'week' in duration_str.lower():
            return 7  # 1 week as 7 days
        else:
            # Try to extract number of days if format is different
            num = int(''.join(filter(str.isdigit, duration_str)))
            return num
    except:
        return 30  # Default to 30 days if parsing fails

def enrolled_plans(request):
    try:
        member_profile = get_object_or_404(Signup, user=request.user)
        enrolled_plans = Enroll.objects.filter(register=member_profile).select_related(
            'package', 
            'package__packagename', 
            'package__category'
        ).order_by('-creationdate')
        
        today = timezone.now().date()
        
        for enroll in enrolled_plans:
            # Convert duration to days
            duration_days = parse_duration(enroll.package.packageduration)
            
            # Calculate remaining days
            expiry_date = enroll.creationdate.date() + timedelta(days=duration_days)
            remaining_days = (expiry_date - today).days
            
            # Prepare display values
            enroll.remaining_days = remaining_days
            enroll.expiry_date = expiry_date
            enroll.duration_display = enroll.package.packageduration
            
            if remaining_days > 0:
                enroll.plan_status = "Active"
                enroll.status_badge = "bg-success"
                enroll.days_display = f"{remaining_days} day{'s' if remaining_days != 1 else ''} remaining"
            elif remaining_days == 0:
                enroll.plan_status = "Expiring Today"
                enroll.status_badge = "bg-warning"
                enroll.days_display = "Expires today"
            else:
                enroll.plan_status = "Expired"
                enroll.status_badge = "bg-danger"
                enroll.days_display = f"Expired {abs(remaining_days)} day{'s' if abs(remaining_days) != 1 else ''} ago"
            
            # Correct way to get payment status
            enroll.payment_status = "Paid" if enroll.status == 1 else "Unpaid"
            enroll.payment_status_badge = "bg-success" if enroll.status == 1 else "bg-danger"

        context = {
            'enrolled_plans': enrolled_plans,
            'member': member_profile,
            'today': today
        }
        return render(request, 'enrolled_plans.html', context)

    except Exception as e:
        print(f"Error: {str(e)}")
        return render(request, 'enrolled_plans.html', {'error': str(e)})
    
from django.shortcuts import redirect
from django.contrib import messages
from .models import Enroll, Package

def renew_plan(request, enroll_id):
    try:
        old_enroll = Enroll.objects.get(id=enroll_id, register__user=request.user)
        
        # Create new enrollment with same package
        new_enroll = Enroll.objects.create(
            package=old_enroll.package,
            register=old_enroll.register,
            status=1,  # Set as unpaid initially
            # Other fields...
        )
        
        # Redirect to payment page
        messages.success(request, "Plan renewed successfully! Please complete the payment.")
        return redirect('payment_form', enroll_id=new_enroll.id)
        
    except Exception as e:
        messages.error(request, f"Error renewing plan: {str(e)}")
        return redirect('enrolled_plans')  
    
from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from .models import Enroll, Payment

def view_invoice(request, enroll_id):
    try:
        enroll = get_object_or_404(Enroll, id=enroll_id, register__user=request.user)
        payment = Payment.objects.filter(enroll=enroll).first()
        
        # Determine payment status
        payment_status = "Paid" if (payment and payment.status == 1) else "Unpaid"
        status_badge = "bg-success" if payment_status == "Paid" else "bg-danger"
        
        context = {
            'enroll': enroll,
            'payment': payment,
            'date': timezone.now().date(),
            'payment_status': payment_status,
            'status_badge': status_badge
        }
        
        return render(request, 'invoice.html', context)
        
    except Exception as e:
        messages.error(request, f"Error loading invoice: {str(e)}")
        return redirect('enrolled_plans')

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .models import MemberAttendance, Signup
from django.db.models import Count

@login_required
def view_attendance(request):
    member_profile = get_object_or_404(Signup, user=request.user)
    
    # Get all attendance records ordered by date
    attendance_records = MemberAttendance.objects.filter(
        member=member_profile
    ).order_by('-date')
    
    # Get total count
    total_attendance = attendance_records.count()
    
    context = {
        'attendance_records': attendance_records,
        'total_attendance': total_attendance,
    }
    return render(request, 'Memberview_attendance.html', context)

