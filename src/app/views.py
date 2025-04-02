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
            if user.is_active ==0:
                messages.error(request,"not verified")
            if user.is_staff:
                messages.success(request, "Invalid User")
                return redirect('user_login')
            else:
                login(request, user)
                messages.success(request, "User Login Successful")
                return redirect('index')
        else:
            messages.success(request, "Invalid User")
            return redirect('user_login')
    return render(request, 'user_login.html', locals())



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
        fname = request.POST['firstname']
        lname = request.POST['secondname']
        email = request.POST['email']
        mobile = request.POST['mobile']
        address = request.POST['address']

        user = User.objects.filter(id=request.user.id).update(first_name=fname, last_name=lname, email=email)
        Signup.objects.filter(user=request.user).update(mobile=mobile, address=address)
        messages.success(request, "Updation Successful")
        return redirect('user_profile')
    data = Signup.objects.get(user=request.user)
    return render(request, "user_profile.html", locals())

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
def booking_history(request):
    data = Signup.objects.get(user=request.user)
    data = Booking.objects.filter(register=data)
    return render(request, "booking_history.html", locals())

@login_required(login_url='/admin_login/')
def new_booking(request):
    action = request.GET.get('action')
    data = Booking.objects.filter()
    if action == "New":
        data = data.filter(status="1")
    elif action == "Partial":
        data = data.filter(status="2")
    elif action == "Full":
        data = data.filter(status="3")
    elif action == "Total":
        data = data.filter()
    if request.user.is_staff:
        return render(request, "admin/new_booking.html", locals())
    else:
        return render(request, "booking_history.html", locals())


def booking_detail(request, pid):
    data = Booking.objects.get(id=pid)
    if request.method == "POST":
        price = request.POST['price']
        status = request.POST['status']
        data.status = status
        data.save()
        Paymenthistory.objects.create(booking=data, price=price, status=status)
        messages.success(request, "Action Updated")
        return redirect('booking_detail', pid)
    payment = Paymenthistory.objects.filter(booking=data)
    if request.user.is_staff:
        return render(request, "admin/admin_booking_detail.html", locals())
    else:
        return render(request, "user_booking_detail.html", locals())

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

def deleteBooking(request, pid):
    booking = Booking.objects.get(id=pid)
    booking.delete()
    messages.success(request, "Delete Successful")
    return redirect('new_booking')

def bookingReport(request):
    data = None
    data2 = None
    if request.method == "POST":
        fromdate = request.POST['fromdate']
        todate = request.POST['todate']

        data = Booking.objects.filter(creationdate__gte=fromdate, creationdate__lte=todate)
        data2 = True
    return render(request, "admin/bookingReport.html", locals())

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
# def booking(request):
#     booking = None
#     bookinged = Booking.objects.filter(register__user=request.user)
#     bookinged_list = [i.policy.id for i in bookinged]
#     data = Package.objects.filter().exclude(id__in=bookinged_list)
#     if request.method == "POST":
#         booking = Package.objects.filter()
#         booking = BookingForm(request.POST, request.FILES, instance=booking)
#         if booking.is_valid():
#             booking = booking.save()
#             booking.bookingnumber = random_with_N_digits(10)
#             data.booking = booking
#             data.save()
#         Booking.objects.create(package=booking)
#         messages.success(request, "Action Updated")
#         return redirect('booking')
#     return render(request, "/", locals())

@login_required(login_url='/user_login/')
def apply_booking(request, pid):
    package = get_object_or_404(Package, id=pid)
    register = get_object_or_404(Signup, user=request.user)

    booking = Booking.objects.create(
        package=package,
        register=register,
        bookingnumber=random_with_N_digits(10)
    )

    messages.success(request, 'Booking Applied')
    
    payment_url = reverse('payment_view')

    context = {
      'action_url': payment_url,
        'booking_id': booking.id,
        'amount': package.price,
    }

    # Return an HttpResponse with a hidden form for POST redirect
    return render(request, 'hidden_post_form.html', context)

from django.shortcuts import render, redirect
from django.http import HttpResponseBadRequest, JsonResponse
from django.urls import reverse
from django.conf import settings
from .models import Payment
import uuid
import hashlib
import base64
import hmac
# Function to generate the signature for eSewa
def generate_signature(amount, transaction_uuid, product_code, secret):
    hash_string = f"total_amount={amount},transaction_uuid={transaction_uuid},product_code={product_code}"

    # Encode both secret and hash_string to bytes using utf-8
    secret_bytes = secret.encode('utf-8')
    hash_string_bytes = hash_string.encode('utf-8')
    
    hmac_sha256 = hmac.new(secret_bytes, hash_string_bytes, hashlib.sha256)
    digest = hmac_sha256.digest()
    signature = base64.b64encode(digest).decode('utf-8')
    print(signature)
    # Encode in Base64
    return signature

def payment_view(request):
    print(request)
    if request.method == 'POST':
        # Get form data
        amount = float(request.POST.get('amount'))  # Convert to float for calculations
        full_name = request.POST.get('full_name')
        phone_number = request.POST.get('phone_number')

        # Generate a unique transaction UUID
        transaction_uuid = str(uuid.uuid4())

        # Secret key (stored securely in settings)
        secret = settings.ESEWA_SECRET_KEY

        # Ensure correct total amount
        tax_amount = 0
        service_charge = 0
        delivery_charge = 0
        total_amount = amount + tax_amount + service_charge + delivery_charge

        # Generate eSewa signature
        signature = generate_signature(total_amount, transaction_uuid, "EPAYTEST", secret)
        print(signature)
        user=User.objects.get(username=request.user)
        booking=Booking.objects.get(id=request.POST.get("booking_id"))
        print(booking)
        print(request.user.id)
        # Save payment data in the database
        payment = Payment.objects.create(
            user=request.user,
            transaction_uuid=transaction_uuid,
            amount=total_amount,
            signature=signature,
            success_url=request.build_absolute_uri(reverse('payment_success')),
            failure_url=request.build_absolute_uri(reverse('payment_failure')),
        )
        print(payment)
        # Prepare data to send to the payment form
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
    return render(request, 'payment/payment_success.html')

def payment_failure(request):
    return render(request, 'payment/payment_failure.html')

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib import messages

def trainer_login(request):
    if request.method == "POST":
        username = request.POST.get("username")  
        password = request.POST.get("password")
        print(username,password)
        if not username or not password:
            messages.error(request, "Username and Password are required.")
            return redirect("trainer_login")

        user = authenticate(request, username=username, password=password)
        trainer= Trainer.objects.get(user_id=user.id)
        print(trainer)
        if( trainer.is_verified==0):
            messages.error(request,"Not verified")
            return render(request,"trainer_login.html")
        if user is not None:
            login(request, user)
            return render(request,"Trainers/trainer_page.html")  
        else:
            messages.error(request, "Invalid username or password.")
            return redirect("trainer_login")

    return render(request, "trainer_login.html")
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt
def verify_user(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_id = data.get("user_id")
            user = User.objects.get(id=user_id)
            print(user)
            user.is_active = 1
            user.save()
            return JsonResponse({"success": True})
        except Signup.DoesNotExist:
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
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import Signup




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

def delete_trainer(request, trainer_id):
    try:
        trainer = Trainer.objects.get(id=trainer_id)
        trainer.delete()
        return JsonResponse({"success": True})
    except Trainer.DoesNotExist:
        return JsonResponse({"success": False, "error": "Trainer not found"})
    
def verify_trainer(request):
    trainer_id = request.POST.get('trainer_id')
    print(trainer_id)
    
    if not trainer_id:
        return HttpResponseBadRequest("Trainer ID is required.")
        
    try:
        trainer_id = int(trainer_id)
    except ValueError:
        return HttpResponseBadRequest("Invalid trainer ID format.")

    trainer = get_object_or_404(Trainer, user_id=trainer_id)
    
    # Toggle the verification status
    trainer.is_verified = not trainer.is_verified
    trainer.save()
    
    # Redirect to the trainer registration page or wherever you want
    return redirect('reg_trainer')

from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Class, Trainer

def add_class(request):
    if request.method == "POST":
        class_name = request.POST.get('class_name')
        description = request.POST.get('description')
        schedule = request.POST.get('schedule')
        trainer_id = request.POST.get('trainer')  # Get trainer ID from the form
        
        trainer = Trainer.objects.get(id=trainer_id) if trainer_id else None

        # Create and save the class instance
        new_class = Class.objects.create(
            class_name=class_name,
            description=description,
            schedule=schedule,
            trainer=trainer
        )
        messages.success(request, "Class added successfully!")
        return redirect('addclasses.html')  # Redirect to the same page or another

    trainers = Trainer.objects.all()  # Fetch all trainers for the dropdown
    return render(request, 'admin/addclasses.html', {'trainers': trainers})

    
