Java.perform(function() {
    var MainActivity = Java.use("com.christmas.lottery.MainActivity");
    var Toast = Java.use("android.widget.Toast");

    // pass the generated ticket code to validate function
    MainActivity.validateTicketCodeWithBackend.implementation = function() {
        var ticketCode = this.generateTicketCode();
        console.log(ticketCode);
        this.validateTicketCodeWithBackend(ticketCode);
    };

    // hook the notif that contains flag
    Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int').implementation = function(context, text, duration) {
        var flag = text.toString();
        console.log(flag);
    };
});