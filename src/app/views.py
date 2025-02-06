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
                return redirect('admin_home')
            else:
                messages.success(request, "Invalid Credentials, Please try again")
                return redirect('index')
    package = Package.objects.filter().order_by('id')[:5]
    return render(request, 'index.html', locals())

def registration(request):
    if request.method == "POST":
        fname = request.POST['firstname']
        lname = request.POST['secondname']
        email = request.POST['email']
        pwd = request.POST['password']
        mobile = request.POST['mobile']
        address = request.POST['address']

        user = User.objects.create_user(first_name=fname, last_name=lname, email=email, password=pwd, username=email)
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

def admin_home(request):
    if not request.user.is_authenticated:
        return redirect('admin_login')
    totalcategory = Category.objects.all().count()
    totalpackagetype = Packagetype.objects.all().count()
    totalpackage = Package.objects.all().count()
    totalbooking = Booking.objects.all().count()
    New = Booking.objects.filter(status="1")
    Partial = Booking.objects.filter(status="2")
    Full = Booking.objects.filter(status="3")
    return render(request, 'admin/admin_home.html', locals())

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
def reg_user(request):
    data = Signup.objects.all()
    d = {'data': data}
    return render(request, "admin/reg_user.html", locals())

@login_required(login_url='/admin_login/')
def delete_user(request, pid):
    data = Signup.objects.get(id=pid)
    data.delete()
    messages.success(request, "Delete Successful")
    return redirect('reg_user')

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
from django.http import JsonResponse
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
