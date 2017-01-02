/**
 * Created by eduardotech on 27/12/16.
 */
$(window).scroll(function () {
    if ($(document).scrollTop() > 800){

        $('nav').addClass('appear');
    }
    else {
        $('nav').removeClass('appear');
    }
});

