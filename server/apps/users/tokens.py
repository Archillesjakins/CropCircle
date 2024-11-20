from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six

class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp) + 
            six.text_type(user.is_active)
        )

email_verification_token = EmailVerificationTokenGenerator()

# class VerifyEmailView(generics.GenericAPIView):
#     permission_classes = (AllowAny,)

#     def get(self, request, uid, token):
#         try:
#             user = User.objects.get(pk=uid)
#         except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#             user = None

#         if user is not None and email_verification_token.check_token(user, token):
#             user.is_active = True
#             user.save()
#             return Response(
#                 {"message": "Email verified successfully"}, 
#                 status=status.HTTP_200_OK
#             )
#         return Response(
#             {"error": "Invalid verification link"}, 
#             status=status.HTTP_400_BAD_REQUEST
#         )

# class RegisterView(generics.CreateAPIView):
#     permission_classes = (AllowAny,)
#     serializer_class = RegisterSerializer

#     def perform_create(self, serializer):
#         user = serializer.save()
#         token = email_verification_token.make_token(user)
        
#         # Build verification URL
#         verification_url = self.request.build_absolute_uri(
#             reverse('verify-email-confirm', kwargs={'uid': user.pk, 'token': token})
#         )
        
#         # Send verification email
#         send_mail(
#             'Verify your email',
#             f'Please click the link to verify your email: {verification_url}',
#             settings.DEFAULT_FROM_EMAIL,
#             [user.email],
#             fail_silently=False,
#         )