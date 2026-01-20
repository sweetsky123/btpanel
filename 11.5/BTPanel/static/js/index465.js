import{a5 as n,D as e}from"./utils-lib.js?v=1768643427";import{c as o,r as _,e as s,x as i,O as l,z as m,d as c}from"./base-lib.js?v=1768643427";import"./__commonjsHelpers__.js?v=1768643427";const y=o({__name:"index",setup(p){const a=_("safeScan"),r=c(()=>e(()=>import("./index528.js?v=1768643427"),__vite__mapDeps([]),import.meta.url)),{BtTabs:t}=n({type:"card",value:a,options:[{label:"安全扫描",name:"safeScan",lazy:!0,render:()=>s(r,null,null)},{label:"违规词检测",name:"wordDetection",lazy:!0,render:()=>e(()=>import("./index529.js?v=1768643427"),__vite__mapDeps([]),import.meta.url)},{label:"动态查杀",name:"dynamicKilling",lazy:!0,render:()=>e(()=>import("./index530.js?v=1768643427"),__vite__mapDeps([]),import.meta.url)}]});return(u,d)=>(i(),l(m(t)))}});export{y as default};
function __vite__mapDeps(indexes) {
  if (!__vite__mapDeps.viteFileDeps) {
    __vite__mapDeps.viteFileDeps = []
  }
  return indexes.map((i) => __vite__mapDeps.viteFileDeps[i])
}
