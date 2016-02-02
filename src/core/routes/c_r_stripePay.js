'use strict';
/**
 * Stripe routes
 *
 * @module core/routes/c_r_stripe
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
module.exports = function(app, lib) {

  var route, method, id;

  /**
   * Donatations
   *
   * @param route /stripe/donate
   * @param method POST
   * @returns {Array} data or error message
   */
  route = '/stripe/donate',
    method = 'post',
    id = method + ',' + route;
  app.appCfg.jsonSchema[id] = {
    body: {
      type: 'object',
      strict: true,
      properties: {
        amount: {
          type: 'number'
        },
        number: {
          type: 'string'
        },
        name: {
          type: 'string'
        },
        expiry: {
          type: 'string'
        },
        cvc: {
          type: 'string'
        },
        currency: {
          type: 'string'
        },
        email: {
          type: [
            'null',
            'string'
          ]
        },
        customer: {
          type: [
            'null',
            'number'
          ]
        }
      },
      required: [
        'amount',
        'number',
        'name',
        'expiry',
        'cvc',
        'currency'
      ]
    }
  };
  app.post(route, lib.core.jsonSchema(id), function donate(req, res, next) {
    lib.core.stripePay.donate(req, function(err, data) {
      if (err) {
        return next(app.appErr(err));
      }
      res.json(data);
    });
  });
};
