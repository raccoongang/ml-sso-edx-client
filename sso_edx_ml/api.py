from course_modes.models import CourseMode
from django.core.exceptions import ObjectDoesNotExist
from enrollment import api
from enrollment.errors import CourseNotFoundError, CourseEnrollmentError, CourseEnrollmentExistsError
from opaque_keys import InvalidKeyError
from opaque_keys.edx.keys import CourseKey
from openedx.core.lib.api.permissions import ApiKeyHeaderPermission
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from student.models import User


class EnrollmentCourse(APIView):

    permission_classes = ApiKeyHeaderPermission,

    def post(self, request):
        email = request.DATA.get('email')
        course_id = request.DATA.get('course_id')
        mode = request.DATA.get('mode', CourseMode.HONOR)

        if not course_id:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"Course ID must be specified to create a new enrollment."}
            )

        try:
            course_id = CourseKey.from_string(course_id)
        except InvalidKeyError:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"No course '{course_id}' found for enrollment".format(course_id=course_id)}
            )

        if not email:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"message": u"User email must be specified to create a new enrollment."}
            )

        try:
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            return Response(
                status=status.HTTP_406_NOT_ACCEPTABLE,
                data={
                    'message': u'The user {} does not exist.'.format(email)
                }
            )

        try:
            enrollment = api.get_enrollment(user.username, unicode(course_id))
            if not enrollment:
                api.add_enrollment(user.username, unicode(course_id), mode=mode)
                return Response(status=status.HTTP_201_CREATED)
            return Response(status=status.HTTP_200_OK)
        except CourseNotFoundError:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "message": u"No course '{course_id}' found for enrollment".format(course_id=course_id)
                }
            )
        except CourseEnrollmentExistsError as error:
            return Response(data=error.enrollment)
        except CourseEnrollmentError:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "message": (
                        u"An error occurred while creating the new course enrollment for user "
                        u"'{username}' in course '{course_id}'"
                    ).format(username=user.username, course_id=course_id)
                }
            )
