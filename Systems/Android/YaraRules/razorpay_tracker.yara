import "androguard"

rule RazorPayActivity
{
	meta:
		description = "All RazorPay SDK Apps"
	condition:
		androguard.activity("com.razorpay.CheckoutActivity")		
}