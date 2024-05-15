import { getRegions } from "../api.js";
import Region from "./region.js";

class RegionList extends HTMLElement {
    #regions = new Map();

    connectedCallback() {
        this.updateContent().then();
    }

    async updateContent() {
        await getRegions(data => {
            for (const { id, ...props } of data) {
                let region = new Region();
                region.regionId = id;
                region.regionModel = props;
                this.#regions.set(id, region);
                this.appendChild(region);
            }
        });
    }
}

customElements.define("lumisync-region-list", RegionList);

export default RegionList;