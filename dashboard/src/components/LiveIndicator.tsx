interface Props {
  isLive: boolean
}

export default function LiveIndicator({ isLive }: Props) {
  return (
    <div className="flex items-center gap-1.5 ml-3">
      <div className={`w-2 h-2 rounded-full ${isLive ? 'bg-[#ff3366] live-pulse' : 'bg-[#4a4a5a]'}`} />
      <span className={`text-xs font-bold ${isLive ? 'text-[#ff3366]' : 'text-[#4a4a5a]'}`}>
        {isLive ? 'LIVE' : 'OFFLINE'}
      </span>
    </div>
  )
}