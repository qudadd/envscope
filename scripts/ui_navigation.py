"""Use the actual visible menu in desktop UI acceptance tests."""
from playwright.sync_api import expect


def open_page(page, name):
    expect(page.locator('html')).not_to_have_attribute('data-operation-busy', 'true', timeout=30000)
    if name != 'audit' and not page.locator('#more-menu').evaluate('(node)=>node.open'):
        page.locator('#more-menu>summary').click()
    page.locator(f'.tab[data-page="{name}"]').click()


def open_details(page, selector):
    if not page.locator(selector).evaluate('(node)=>node.open'):
        page.locator(selector + '>summary').click()
