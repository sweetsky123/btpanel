import{D as t,ao as m}from"./utils-lib.js?v=1768643427";import{c as _,r,v as i,x as d,O as f,z as l,R as c}from"./base-lib.js?v=1768643427";import"./__commonjsHelpers__.js?v=1768643427";const E=_({__name:"index",props:{compData:{default:()=>{}}},setup(n){const a=n,e=r(typeof a.compData=="string"?a.compData:"setDefaultPage"),s=r([{label:"页面模板",name:"setDefaultPage",lazy:!0,render:()=>t(()=>import("./default-page2.js?v=1768643427"),__vite__mapDeps([]),import.meta.url)},{label:"默认站点",name:"defaultSite",lazy:!0,render:()=>t(()=>import("./defalut-site2.js?v=1768643427"),__vite__mapDeps([]),import.meta.url)},{label:"HTTPS管理",name:"httpsOfficersSite",lazy:!0,render:()=>t(()=>import("./anti-channel-site2.js?v=1768643427"),__vite__mapDeps([]),import.meta.url)}]);return i(()=>{}),(D,o)=>{const p=m;return d(),f(p,{class:"w-full h-full",type:"left-bg-card",modelValue:l(e),"onUpdate:modelValue":o[0]||(o[0]=u=>c(e)?e.value=u:null),options:l(s)},null,8,["modelValue","options"])}}});export{E as default};
function __vite__mapDeps(indexes) {
  if (!__vite__mapDeps.viteFileDeps) {
    __vite__mapDeps.viteFileDeps = []
  }
  return indexes.map((i) => __vite__mapDeps.viteFileDeps[i])
}
