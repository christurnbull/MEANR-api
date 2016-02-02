'use strict';
/**
 * Stripe library
 *
 * @module core/lib/c_l_stripe
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(app, db, lib) {

  return {

    /**
     * Donate
     */
    donate: function(inObj, cb) {
      var number, expiry, cvc, currency;
      try {
        number = parseInt(inObj.body.number);
        var exp = inObj.body.expiry.split('/');
        expiry = {
          month: parseInt(exp[0]),
          year: parseInt(exp[1])
        };
        cvc = parseInt(inObj.body.cvc);
        currency = inObj.body.currency.toLowerCase();
      } catch (e) {
        return cb([{
          msg: 'Invalid details.',
          desc: 'Payment has not been made'
        }], null);
      }
      // stripe supported zero-decimal currencies
      var zeroDecimal = {
        BIF: 'Burundian Franc',
        CLP: 'Chilean Peso',
        DJF: 'Djiboutian Franc',
        GNF: 'Guinean Franc',
        JPY: 'Japanese Yen',
        KMF: 'Comorian Franc',
        KRW: 'South Korean Won',
        MGA: 'Malagasy Ariary',
        PYG: 'Paraguayan Guaraní',
        RWF: 'Rwandan Franc',
        VND: 'Vietnamese Đồng',
        VUV: 'Vanuatu Vatu',
        XAF: 'Central African Cfa Franc',
        XOF: 'West African Cfa Franc',
        XPF: 'Cfp Franc'
      };
      var amount = inObj.body.amount;
      if (!zeroDecimal.hasOwnProperty(currency.toUpperCase())) {
        // all other supoprted currencies are decimal
        amount = amount * 100;
      }
      var stripeData = {
        amount: amount,
        currency: currency.toLowerCase(),
        description: 'Donation from ' + inObj.body.name,
        source: {
          number: number,
          exp_month: expiry.month,
          exp_year: expiry.year,
          cvc: cvc,
          object: 'card',
          customer: inObj.body.customer,
          email: inObj.body.email
        }
      };
      lib.core.stripe.charges.create(stripeData, function(err, charge) {
        if (err) {
          return cb(err, null);
        }
        // save to database etc...
        return cb(null, [charge]);
      });
    }
  };
};
