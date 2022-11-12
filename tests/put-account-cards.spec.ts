import { test, expect } from "@playwright/test";
import { parameters } from "./constants/parameters";
import { putCard } from "./constants/functions";

const account_id = parameters.account_id;
const owned_card = parameters.existing_card;
const nonowned_card = parameters.nonexisting_card;

test.describe("PUT cards tests", () => {
  test("PUT Cards request updates card existing in collection", async ({
    request,
  }) => {
    let price = 1.0;
    let qty = 1;
    let res = await putCard(request, owned_card, price, qty);
    expect(res.ok()).toBeTruthy();
    let data = JSON.parse((await res.body()).toString());
    expect(data).not.toHaveLength(0);
    expect(data[0].account_id).toEqual(account_id);
    expect(data[0].scry_id).toEqual(owned_card.scry_id);
    expect(data[0].card_name).toEqual(owned_card.card_name);
    expect(data[0].quantity).toEqual(owned_card.quantity + qty);
    expect(data[0].price).toEqual((owned_card.price + price).toString());
  });

  test("PUT Cards request cannot update unowned card", async ({
    request,
  }) => {
    let price = 1.0;
    let qty = 1;
    let res = await putCard(request, nonowned_card, price, qty);
    expect(res.ok()).toBeFalsy();
  });

  test.afterEach(async ({ request }) => {
    let res = await putCard(request, owned_card);
    expect(res.ok()).toBeTruthy();
  });
});
