export function getSelect(id: string): HTMLSelectElement {
    const el = document.getElementById(id);
    if (!(el instanceof HTMLSelectElement)) throw new Error(`element #${id} is not a select`);
    return el;
}

export function getInput(id: string): HTMLInputElement {
    const el = document.getElementById(id);
    if (!(el instanceof HTMLInputElement)) throw new Error(`element #${id} is not an input`);
    return el;
}
