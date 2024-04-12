const stripe = stripe('pk_test_51P1UH6LaJzLnoVtQKi5JED0TWxkRTWbwpQLEoyp6A0CdtIKYGltu8wmGHgvR0tKaVcPuioP7mM9Blo14M0EgC17A006gyPAOlr');
 const paymentButton = document.querySelector('#paymentButton');
 
 paymentButton.addEventListener('click', () => {
   stripe.redirectToCheckout({
     sessionId: sessionId
   })
 });