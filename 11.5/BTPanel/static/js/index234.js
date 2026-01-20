import{ao as _,D as n,_ as d}from"./utils-lib.js?v=1768643427";import{c as i,r as f,x as b,y as D,e as t,z as k,R as v,d as r}from"./base-lib.js?v=1768643427";import"./__commonjsHelpers__.js?v=1768643427";const x={class:"p-[20px] h-full"},B=i({__name:"index",props:{compData:{default:()=>[]}},setup(s){const c=r(()=>n(()=>import("./index451.js?v=1768643427"),__vite__mapDeps([]),import.meta.url)),p=r(()=>n(()=>import("./index452.js?v=1768643427"),__vite__mapDeps([]),import.meta.url)),a=s,e=f("routeBackup"),l=[{label:"常规备份",name:"routeBackup",lazy:!0,render:()=>t(p,{compData:a.compData},null)},{label:"增量备份",name:"incrementBackup",lazy:!0,render:()=>t(c,{compData:a.compData},null)}];return(V,o)=>{const m=_;return b(),D("div",x,[t(m,{type:"card",modelValue:k(e),"onUpdate:modelValue":o[0]||(o[0]=u=>v(e)?e.value=u:null),options:l,class:"bt-tabs bt-tabs-card"},null,8,["modelValue"])])}}}),A=d(B,[["__scopeId","data-v-ce9629be"]]);export{A as default};
function __vite__mapDeps(indexes) {
  if (!__vite__mapDeps.viteFileDeps) {
    __vite__mapDeps.viteFileDeps = []
  }
  return indexes.map((i) => __vite__mapDeps.viteFileDeps[i])
}
